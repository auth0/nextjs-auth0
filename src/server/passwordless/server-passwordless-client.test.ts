/**
 * Unit tests for ServerPasswordlessClient — App Router path (next/headers mock).
 *
 * The flow-level tests for Pages Router and MCD resolver mode live in
 * passwordless-server.flow.test.ts. This file covers the App Router
 * getCookies() integration which requires next/headers to be mocked at
 * the module level.
 */
import { NextRequest, NextResponse } from "next/server.js";
import { ResponseCookies } from "@edge-runtime/cookies";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../../test/defaults.js";
import { AuthClientProvider } from "../auth-client-provider.js";
import { AuthClient } from "../auth-client.js";
import { StatelessSessionStore } from "../session/stateless-session-store.js";
import { TransactionStore } from "../transaction-store.js";
import { ServerPasswordlessClient } from "./server-passwordless-client.js";

// Shared mutable headers that the mocked next/headers cookies() returns.
// Tests reset this in beforeEach so each test gets a clean slate.
let mockCookieHeaders: Headers;

vi.mock("next/headers.js", () => ({
  cookies: vi.fn(async () => new ResponseCookies(mockCookieHeaders)),
  headers: vi.fn(() => new Headers())
}));

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  email: "user@example.com",
  phoneNumber: "+14155550100",
  verificationCode: "123456",
  sub: "auth0|test-user-id",
  sid: "test-sid"
};

let keyPair: jose.GenerateKeyPairResult;

const authorizationServerMetadata = createAuthorizationServerMetadata(
  DEFAULT.domain
);

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json(authorizationServerMetadata)
  ),
  http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-1", alg: "RS256", use: "sig" }]
    });
  })
);

setupMswLifecycle(server);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair("RS256");
});

async function makeIdToken(
  claims: Record<string, unknown> = {}
): Promise<string> {
  return new jose.SignJWT({ sub: DEFAULT.sub, sid: DEFAULT.sid, ...claims })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(`https://${DEFAULT.domain}`)
    .setAudience(DEFAULT.clientId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);
}

function makePasswordlessClient(): ServerPasswordlessClient {
  return new ServerPasswordlessClient({
    forRequest: async () =>
      new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: "test-secret-long-enough-for-hs256-algorithm",
        transactionStore: new TransactionStore({
          secret: "test-secret-long-enough-for-hs256-algorithm"
        }),
        sessionStore: new StatelessSessionStore({
          secret: "test-secret-long-enough-for-hs256-algorithm"
        }),
        routes: getDefaultRoutes()
      }),
    isResolverMode: false
  } as unknown as AuthClientProvider);
}

// ---------------------------------------------------------------------------
// start() — App Router path
// ---------------------------------------------------------------------------

describe("ServerPasswordlessClient.start() — App Router", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  describe("magic link (send: link)", () => {
    it("writes a transaction cookie to next/headers on success", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json({}, { status: 200 })
        )
      );

      await makePasswordlessClient().start({
        connection: "email",
        email: DEFAULT.email,
        send: "link"
      });

      const setCookie = mockCookieHeaders.get("set-cookie");
      expect(setCookie).toBeTruthy();
      expect(setCookie).toMatch(/HttpOnly/i);
    });

    it("throws PasswordlessStartError and does not write cookie on Auth0 failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json(
            {
              error: "bad.connection",
              error_description: "Connection not found."
            },
            { status: 400 }
          )
        )
      );

      await expect(
        makePasswordlessClient().start({
          connection: "email",
          email: DEFAULT.email,
          send: "link"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessStartError",
        error: "bad.connection"
      });

      expect(mockCookieHeaders.get("set-cookie")).toBeNull();
    });
  });

  describe("email OTP (send: code)", () => {
    it("succeeds without calling getCookies()", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json({}, { status: 200 })
        )
      );

      await expect(
        makePasswordlessClient().start({
          connection: "email",
          email: DEFAULT.email,
          send: "code"
        })
      ).resolves.toBeUndefined();

      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });
  });

  describe("SMS OTP", () => {
    it("succeeds without calling getCookies()", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json({}, { status: 200 })
        )
      );

      await expect(
        makePasswordlessClient().start({
          connection: "sms",
          phoneNumber: DEFAULT.phoneNumber
        })
      ).resolves.toBeUndefined();

      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });
  });

  describe("Pages Router overload (req, res, options)", () => {
    it("succeeds for email OTP and does not touch next/headers", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json({}, { status: 200 })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
        { method: "POST" }
      );
      const res = new NextResponse();

      await expect(
        makePasswordlessClient().start(req, res, {
          connection: "email",
          email: DEFAULT.email,
          send: "code"
        })
      ).resolves.toBeUndefined();

      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });

    it("writes transaction cookie to res for magic link and does not touch next/headers", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
          HttpResponse.json({}, { status: 200 })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
        { method: "POST" }
      );
      const res = new NextResponse();

      await expect(
        makePasswordlessClient().start(req, res, {
          connection: "email",
          email: DEFAULT.email,
          send: "link"
        })
      ).resolves.toBeUndefined();

      // Transaction cookie must land on res, not on next/headers
      expect(res.headers.get("set-cookie")).toBeTruthy();
      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });

    it("throws TypeError when res is missing", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
        { method: "POST" }
      );

      await expect(
        (makePasswordlessClient().start as any)(req, {
          connection: "email",
          email: DEFAULT.email,
          send: "code"
        })
      ).rejects.toThrow(TypeError);
    });
  });
});

// ---------------------------------------------------------------------------
// verify() — App Router path
// ---------------------------------------------------------------------------

describe("ServerPasswordlessClient.verify() — App Router", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("creates a session cookie in next/headers for email OTP", async () => {
    const idToken = await makeIdToken({ email: DEFAULT.email });

    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "test-access-token",
          token_type: "Bearer",
          expires_in: 86400,
          scope: "openid profile email",
          id_token: idToken
        })
      )
    );

    await makePasswordlessClient().verify({
      connection: "email",
      email: DEFAULT.email,
      verificationCode: DEFAULT.verificationCode
    });

    // Session cookie written to next/headers — value is an encrypted JWE blob.
    const setCookie = mockCookieHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/__session=/);
  });

  it("creates a session cookie in next/headers for SMS OTP", async () => {
    const idToken = await makeIdToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "test-access-token",
          token_type: "Bearer",
          expires_in: 86400,
          id_token: idToken
        })
      )
    );

    await makePasswordlessClient().verify({
      connection: "sms",
      phoneNumber: DEFAULT.phoneNumber,
      verificationCode: DEFAULT.verificationCode
    });

    const setCookie = mockCookieHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/__session=/);
  });

  it("throws PasswordlessVerifyError on Auth0 token failure", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json(
          {
            error: "invalid_grant",
            error_description: "Wrong email or verification code."
          },
          { status: 403 }
        )
      )
    );

    await expect(
      makePasswordlessClient().verify({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: "wrong-code"
      })
    ).rejects.toMatchObject({
      name: "PasswordlessVerifyError",
      error: "invalid_grant"
    });

    expect(mockCookieHeaders.get("set-cookie")).toBeNull();
  });

  it("throws TypeError when extra arguments are passed (App Router guard)", async () => {
    await expect(
      (makePasswordlessClient().verify as any)(
        {
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        },
        new NextResponse()
      )
    ).rejects.toThrow(TypeError);
  });

  describe("Pages Router overload (req, res, options)", () => {
    it("writes session cookie to res and not to next/headers", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      const idToken = await makeIdToken({ email: DEFAULT.email });

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
          HttpResponse.json({
            access_token: "test-access-token",
            token_type: "Bearer",
            expires_in: 86400,
            scope: "openid profile email",
            id_token: idToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
        { method: "POST" }
      );
      const res = new NextResponse();

      await makePasswordlessClient().verify(req, res, {
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      expect(res.headers.get("set-cookie")).toBeTruthy();
      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });

    it("throws TypeError when res is missing", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
        { method: "POST" }
      );

      await expect(
        (makePasswordlessClient().verify as any)(req, {
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        })
      ).rejects.toThrow(TypeError);
    });
  });
});
