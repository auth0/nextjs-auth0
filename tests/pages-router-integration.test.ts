import { NextApiRequest, NextApiResponse } from "next";
import { NextRequest, NextResponse } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createNextHeadersMock } from "../src/test/mocks.js";
import { Auth0Client } from "../src/server/client.js";

vi.mock("next/headers.js", () => createNextHeadersMock());

const DEFAULT = {
  domain: "test.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.com",
  secret: "super-secret-32-character-string"
};

/**
 * Creates a mock NextApiRequest for testing.
 */
function createMockNextApiRequest(
  url: string,
  options: {
    method?: string;
    body?: any;
    cookies?: Record<string, string>;
    headers?: Record<string, string>;
  } = {}
): NextApiRequest {
  const urlObj = new URL(url);
  const { method = "GET", body, cookies = {}, headers = {} } = options;

  return {
    method,
    url: urlObj.pathname + urlObj.search,
    headers: {
      host: urlObj.host,
      ...headers
    },
    body,
    cookies,
    query: Object.fromEntries(urlObj.searchParams.entries())
  } as unknown as NextApiRequest;
}

/**
 * Creates a mock NextApiResponse that records what was written to it.
 */
function createMockNextApiResponse() {
  const headers: Record<string, string | string[]> = {};
  const writtenData: any[] = [];
  let ended = false;

  const res = {
    statusCode: 200,
    statusMessage: "OK",
    setHeader: vi.fn((name: string, value: string | string[]) => {
      headers[name.toLowerCase()] = value;
      return res;
    }),
    getHeader: vi.fn((name: string) => headers[name.toLowerCase()]),
    getHeaders: vi.fn(() => headers),
    send: vi.fn((data: any) => {
      writtenData.push(data);
      ended = true;
      return res;
    }),
    end: vi.fn(() => {
      ended = true;
      return res;
    })
  };

  return {
    res: res as unknown as NextApiResponse,
    headers,
    writtenData,
    get ended() {
      return ended;
    }
  };
}

/**
 * Builds an Auth0Client and spies on the per-request AuthClient.handler so the
 * tests exercise handleAuth's dispatch / request-normalization / response
 * writeback without running the full (crypto-heavy) auth flow.
 */
async function createClientWithHandlerSpy(
  impl: (req: NextRequest) => Promise<NextResponse> | NextResponse
) {
  const auth0 = new Auth0Client({
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    appBaseUrl: DEFAULT.appBaseUrl,
    secret: DEFAULT.secret,
    fetch: vi.fn()
  });

  // Static mode returns the same cached AuthClient for every request.
  const authClient = await (auth0 as any).provider.forRequest(new Headers());
  const handlerSpy = vi
    .spyOn(authClient, "handler")
    .mockImplementation((req: any) => Promise.resolve(impl(req)));

  return { auth0, handlerSpy };
}

describe("Pages Router Integration: handleAuth", () => {
  const originalAppBaseUrl = process.env.APP_BASE_URL;

  beforeEach(() => {
    process.env.APP_BASE_URL = DEFAULT.appBaseUrl;
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env.APP_BASE_URL = originalAppBaseUrl;
    vi.restoreAllMocks();
  });

  describe("App Router (NextRequest / Request)", () => {
    it("returns the NextResponse produced by the handler", async () => {
      const { auth0, handlerSpy } = await createClientWithHandlerSpy(() =>
        NextResponse.redirect(`https://${DEFAULT.domain}/authorize?x=1`, 307)
      );

      const response = await auth0.handleAuth(
        new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`)
      );

      expect(handlerSpy).toHaveBeenCalledTimes(1);
      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain("authorize");
    });

    it("passes the normalized request (including query) to the handler", async () => {
      const { auth0, handlerSpy } = await createClientWithHandlerSpy(() =>
        NextResponse.json({ ok: true })
      );

      await auth0.handleAuth(
        new NextRequest(`${DEFAULT.appBaseUrl}/auth/login?organization=org_123`)
      );

      const received = handlerSpy.mock.calls[0][0] as NextRequest;
      expect(received.nextUrl.pathname).toBe("/auth/login");
      expect(received.nextUrl.searchParams.get("organization")).toBe("org_123");
    });

    it("handles a standard Request", async () => {
      const { auth0 } = await createClientWithHandlerSpy(() =>
        NextResponse.redirect(`https://${DEFAULT.domain}/authorize`, 307)
      );

      const response = await auth0.handleAuth(
        new Request(`${DEFAULT.appBaseUrl}/auth/login`)
      );

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });
  });

  describe("Pages Router (NextApiRequest / NextApiResponse)", () => {
    it("writes a redirect (status + location) onto the NextApiResponse", async () => {
      const { auth0, handlerSpy } = await createClientWithHandlerSpy(() =>
        NextResponse.redirect(`https://${DEFAULT.domain}/authorize?x=1`, 307)
      );
      const req = createMockNextApiRequest(`${DEFAULT.appBaseUrl}/auth/login`);
      const { res, headers } = createMockNextApiResponse();

      const result = await auth0.handleAuth(req, res);

      // Pages Router handler returns void.
      expect(result).toBeUndefined();
      expect(handlerSpy).toHaveBeenCalledTimes(1);
      expect(res.statusCode).toBe(307);
      expect(headers["location"] as string).toContain("authorize");
    });

    it("normalizes the NextApiRequest (URL + query) before dispatching", async () => {
      const { auth0, handlerSpy } = await createClientWithHandlerSpy(() =>
        NextResponse.json({ ok: true })
      );
      const req = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login?organization=org_456`
      );
      const { res } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      const received = handlerSpy.mock.calls[0][0] as NextRequest;
      expect(received.nextUrl.pathname).toBe("/auth/login");
      expect(received.nextUrl.searchParams.get("organization")).toBe("org_456");
    });

    it("writes multiple set-cookie headers as an array", async () => {
      const { auth0 } = await createClientWithHandlerSpy(() => {
        const r = NextResponse.json({ ok: true });
        r.headers.append("set-cookie", "a=1; Path=/");
        r.headers.append("set-cookie", "b=2; Path=/");
        return r;
      });
      const req = createMockNextApiRequest(`${DEFAULT.appBaseUrl}/auth/login`);
      const { res, headers } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        "set-cookie",
        expect.any(Array)
      );
      const cookies = headers["set-cookie"] as string[];
      expect(cookies).toHaveLength(2);
      expect(cookies).toEqual(
        expect.arrayContaining(["a=1; Path=/", "b=2; Path=/"])
      );
    });

    it("writes a JSON body and status onto the response", async () => {
      const { auth0 } = await createClientWithHandlerSpy(() =>
        NextResponse.json({ hello: "world" }, { status: 201 })
      );
      const req = createMockNextApiRequest(`${DEFAULT.appBaseUrl}/auth/profile`);
      const { res, writtenData } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      expect(res.statusCode).toBe(201);
      expect(JSON.parse(writtenData[0])).toEqual({ hello: "world" });
    });

    it("ends the response without a body for empty responses", async () => {
      const { auth0 } = await createClientWithHandlerSpy(
        () => new NextResponse(null, { status: 204 })
      );
      const req = createMockNextApiRequest(`${DEFAULT.appBaseUrl}/auth/login`);
      const { res } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      expect(res.statusCode).toBe(204);
      expect(res.end).toHaveBeenCalled();
      expect(res.send).not.toHaveBeenCalled();
    });

    it("reconstructs a urlencoded POST body so the handler can read it", async () => {
      let receivedBody: string | undefined;
      const { auth0 } = await createClientWithHandlerSpy(async (req) => {
        receivedBody = await req.text();
        return new NextResponse(null, { status: 204 });
      });
      const req = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/backchannel-logout`,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          // NextApiRequest.body is already parsed by Next.js.
          body: { logout_token: "the-token" }
        }
      );
      const { res } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      expect(receivedBody).toBeDefined();
      expect(new URLSearchParams(receivedBody!).get("logout_token")).toBe(
        "the-token"
      );
    });

    it("reconstructs a JSON POST body so the handler can read it", async () => {
      let receivedJson: any;
      const { auth0 } = await createClientWithHandlerSpy(async (req) => {
        receivedJson = await req.json();
        return new NextResponse(null, { status: 204 });
      });
      const req = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/mfa/challenge`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: { mfa_token: "abc", challenge_type: "otp" }
        }
      );
      const { res } = createMockNextApiResponse();

      await auth0.handleAuth(req, res);

      expect(receivedJson).toEqual({
        mfa_token: "abc",
        challenge_type: "otp"
      });
    });
  });
});
