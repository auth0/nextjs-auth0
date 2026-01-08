import { NextApiRequest, NextApiResponse } from "next";
import { NextRequest, NextResponse } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Auth0Client } from "../src/server/client.js";
import { AuthClient } from "../src/server/auth-client.js";
import { StatelessSessionStore } from "../src/server/session/stateless-session-store.js";
import { TransactionStore } from "../src/server/transaction-store.js";
import { getDefaultRoutes } from "../src/test/defaults.js";

const DEFAULT = {
  domain: "test.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.com",
  secret: "super-secret-32-character-string"
};

function getMockAuthorizationServer(options: { supportPAR?: boolean } = {}) {
  const { supportPAR = true } = options;

  return vi
    .fn()
    .mockImplementation(
      async (
        input: RequestInfo | URL,
        init?: RequestInit
      ): Promise<Response> => {
        let url: URL;
        if (input instanceof Request) {
          url = new URL(input.url);
        } else {
          url = new URL(input);
        }

        // Discovery endpoint
        if (url.pathname === "/.well-known/openid-configuration") {
          const metadata = {
            issuer: `https://${DEFAULT.domain}`,
            authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
            token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
            userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
            end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`,
            jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
            response_types_supported: ["code"],
            code_challenge_methods_supported: ["S256"],
            scopes_supported: ["openid", "profile", "email"]
          };

          if (supportPAR) {
            (metadata as any).pushed_authorization_request_endpoint =
              `https://${DEFAULT.domain}/oauth/par`;
          }

          return new Response(JSON.stringify(metadata), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        // PAR endpoint
        if (url.pathname === "/oauth/par" && supportPAR) {
          return new Response(
            JSON.stringify({
              request_uri: "urn:ietf:params:oauth:request_uri:test",
              expires_in: 30
            }),
            {
              status: 201,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        return new Response(null, { status: 404 });
      }
    );
}

/**
 * Creates a mock NextApiRequest for testing
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
  const { method = "GET", body = {}, cookies = {}, headers = {} } = options;

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
  } as NextApiRequest;
}

/**
 * Creates a mock NextApiResponse for testing
 */
function createMockNextApiResponse(): NextApiResponse {
  const headers: Record<string, string | string[]> = {};
  let statusCode = 200;
  let statusMessage = "OK";
  const writtenData: any[] = [];

  const res = {
    statusCode,
    statusMessage,
    setHeader: vi.fn((name: string, value: string | string[]) => {
      headers[name.toLowerCase()] = value;
      return res;
    }),
    getHeader: vi.fn((name: string) => headers[name.toLowerCase()]),
    getHeaders: vi.fn(() => headers),
    removeHeader: vi.fn((name: string) => {
      delete headers[name.toLowerCase()];
      return res;
    }),
    status: vi.fn((code: number) => {
      statusCode = code;
      res.statusCode = code;
      return res;
    }),
    redirect: vi.fn((url: string) => {
      res.setHeader("Location", url);
      res.status(302);
      return res;
    }),
    json: vi.fn((data: any) => {
      res.setHeader("Content-Type", "application/json");
      writtenData.push(JSON.stringify(data));
      return res;
    }),
    send: vi.fn((data: any) => {
      writtenData.push(data);
      return res;
    }),
    end: vi.fn(() => res)
  } as unknown as NextApiResponse;

  return res;
}

describe("Pages Router Integration", () => {
  const originalAppBaseUrl = process.env.APP_BASE_URL;

  beforeEach(() => {
    process.env.APP_BASE_URL = DEFAULT.appBaseUrl;
  });

  afterEach(() => {
    process.env.APP_BASE_URL = originalAppBaseUrl;
  });

  describe("AuthClient.handler() with Pages Router", () => {
    let authClient: AuthClient;

    beforeEach(() => {
      vi.clearAllMocks();
      vi.resetModules();

      const secret = DEFAULT.secret;
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: getMockAuthorizationServer()
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("should handle login request with NextApiRequest", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login`
      );
      const mockRes = createMockNextApiResponse();

      await authClient.handler(mockReq, undefined, mockRes);

      expect(mockRes.redirect).toHaveBeenCalled();
      const redirectUrl = (mockRes.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toContain(DEFAULT.domain);
      expect(redirectUrl).toContain("authorize");
    });

    it("should handle login request with NextRequest (App Router)", async () => {
      const request = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`);

      const response = await authClient.handler(request);

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain(DEFAULT.domain);
      expect(response.headers.get("location")).toContain("authorize");
    });

    it("should preserve query parameters in Pages Router", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login?returnTo=/dashboard&organization=org_123`
      );
      const mockRes = createMockNextApiResponse();

      await authClient.handler(mockReq, undefined, mockRes);

      expect(mockRes.redirect).toHaveBeenCalled();
      const redirectUrl = (mockRes.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toContain("organization=org_123");
    });

    it("should normalize HTTP method to uppercase", async () => {
      const mockReq = {
        method: "get",
        url: "/auth/login",
        headers: { host: "example.com" },
        body: {},
        cookies: {},
        query: {}
      } as NextApiRequest;
      const mockRes = createMockNextApiResponse();

      await authClient.handler(mockReq, undefined, mockRes);

      expect(mockRes.redirect).toHaveBeenCalled();
    });
  });

  describe("Auth0Client.handleAuth()", () => {
    let auth0Client: Auth0Client;

    beforeEach(() => {
      vi.clearAllMocks();
      vi.resetModules();

      auth0Client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: DEFAULT.secret,
        fetch: getMockAuthorizationServer()
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("should handle App Router request (NextRequest)", async () => {
      const request = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`);

      const response = await auth0Client.handleAuth(request);

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain("authorize");
    });

    it("should handle App Router request (standard Request)", async () => {
      const request = new Request(`${DEFAULT.appBaseUrl}/auth/login`);

      const response = await auth0Client.handleAuth(request);

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });

    it("should handle Pages Router request (NextApiRequest + NextApiResponse)", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login`
      );
      const mockRes = createMockNextApiResponse();

      const result = await auth0Client.handleAuth(mockReq, mockRes);

      // Pages Router should not return anything (void)
      expect(result).toBeUndefined();
      // But the response should be modified
      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it("should handle organization parameter in App Router", async () => {
      const request = new NextRequest(
        `${DEFAULT.appBaseUrl}/auth/login?organization=org_123`
      );

      const response = await auth0Client.handleAuth(request);

      expect(response.headers.get("location")).toContain("organization=org_123");
    });

    it("should handle organization parameter in Pages Router", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login?organization=org_456`
      );
      const mockRes = createMockNextApiResponse();

      await auth0Client.handleAuth(mockReq, mockRes);

      const redirectUrl = (mockRes.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toContain("organization=org_456");
    });

    it("should route to correct handler based on path in Pages Router", async () => {
      // Test login route
      const loginReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login`
      );
      const loginRes = createMockNextApiResponse();

      await auth0Client.handleAuth(loginReq, loginRes);

      expect(loginRes.redirect).toHaveBeenCalled();
      const loginRedirectUrl = (loginRes.redirect as any).mock.calls[0][0];
      expect(loginRedirectUrl).toContain("authorize");
    });

    it("should handle GET method in Pages Router", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login`,
        { method: "GET" }
      );
      const mockRes = createMockNextApiResponse();

      await auth0Client.handleAuth(mockReq, mockRes);

      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it("should work with custom returnTo parameter in Pages Router", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login?returnTo=/protected/dashboard`
      );
      const mockRes = createMockNextApiResponse();

      await auth0Client.handleAuth(mockReq, mockRes);

      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it("should handle multiple query parameters in Pages Router", async () => {
      const mockReq = createMockNextApiRequest(
        `${DEFAULT.appBaseUrl}/auth/login?organization=org_123&audience=api.example.com&scope=openid%20profile`
      );
      const mockRes = createMockNextApiResponse();

      await auth0Client.handleAuth(mockReq, mockRes);

      const redirectUrl = (mockRes.redirect as any).mock.calls[0][0];
      expect(redirectUrl).toContain("organization=org_123");
    });
  });
});
