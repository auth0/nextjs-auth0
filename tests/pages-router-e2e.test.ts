/**
 * End-to-end Pages Router test for `Auth0Client.handleAuth`.
 *
 * Unlike `pages-router-integration.test.ts` (which spies on `AuthClient.handler`
 * to test dispatch / normalization / writeback in isolation), this suite runs
 * the REAL authentication flow — login → code exchange → callback — through the
 * Pages Router adapter, against a mock authorization server. It proves that:
 *
 *   1. login writes the transaction (`__txn_*`) cookie onto the NextApiResponse,
 *   2. the callback request, carrying that cookie back via the `cookie` header,
 *      is normalized correctly so the handler can read it,
 *   3. the callback completes the code exchange and writes the session cookie.
 *
 * NOTE: This exercises real crypto (PKCE, JWT signing/verification). It is
 * expected to run in CI; some local environments crash the worker due to an
 * unrelated native keychain issue (`SecItemCopyMatching failed -50`).
 */
import { NextApiRequest, NextApiResponse } from "next";
import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createNextHeadersMock } from "../src/test/mocks.js";
import { Auth0Client } from "../src/server/client.js";

vi.mock("next/headers.js", () => createNextHeadersMock());

const DEFAULT = {
  domain: "test.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.com",
  secret: "super-secret-32-character-string",
  sub: "user_e2e_123",
  sid: "sid_e2e_123",
  alg: "RS256"
};

const keyPair = await jose.generateKeyPair(DEFAULT.alg);

const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`,
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["openid", "profile", "email", "offline_access"]
};

/**
 * Mock authorization server: discovery, JWKS, and a token endpoint that returns
 * a signed id_token.
 */
function getMockAuthorizationServer(options: { nonce?: string } = {}) {
  return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const url = input instanceof Request ? new URL(input.url) : new URL(input);

    if (url.pathname === "/.well-known/openid-configuration") {
      return Response.json(authorizationServerMetadata);
    }

    if (url.pathname === "/.well-known/jwks.json") {
      const publicJwk = await jose.exportJWK(keyPair.publicKey);
      return Response.json({ keys: [publicJwk] });
    }

    if (url.pathname === "/oauth/token") {
      const idToken = await new jose.SignJWT({
        sid: DEFAULT.sid,
        nonce: options.nonce ?? "nonce-value",
        auth_time: Math.floor(Date.now() / 1000)
      })
        .setProtectedHeader({ alg: DEFAULT.alg })
        .setSubject(DEFAULT.sub)
        .setIssuedAt()
        .setIssuer(authorizationServerMetadata.issuer)
        .setAudience(DEFAULT.clientId)
        .setExpirationTime("2h")
        .sign(keyPair.privateKey);

      return Response.json({
        token_type: "Bearer",
        access_token: "at_e2e_123",
        refresh_token: "rt_e2e_123",
        id_token: idToken,
        expires_in: 86400
      });
    }

    return new Response(null, { status: 404 });
  });
}

function createMockNextApiRequest(
  url: string,
  options: {
    method?: string;
    body?: any;
    headers?: Record<string, string>;
  } = {}
): NextApiRequest {
  const urlObj = new URL(url);
  const { method = "GET", body, headers = {} } = options;

  return {
    method,
    url: urlObj.pathname + urlObj.search,
    headers: {
      host: urlObj.host,
      ...headers
    },
    body,
    query: Object.fromEntries(urlObj.searchParams.entries())
  } as unknown as NextApiRequest;
}

function createMockNextApiResponse() {
  const headers: Record<string, string | string[]> = {};
  const res = {
    statusCode: 200,
    statusMessage: "OK",
    setHeader: vi.fn((name: string, value: string | string[]) => {
      headers[name.toLowerCase()] = value;
      return res;
    }),
    getHeader: vi.fn((name: string) => headers[name.toLowerCase()]),
    send: vi.fn(() => res),
    end: vi.fn(() => res)
  };
  return { res: res as unknown as NextApiResponse, headers };
}

/** Parse a set-cookie value (array or string) into a `name=value; ...` cookie header. */
function setCookieToCookieHeader(setCookie: string | string[]): string {
  const values = Array.isArray(setCookie) ? setCookie : [setCookie];
  return values
    .map((c) => c.split(";")[0]) // keep only `name=value`
    .filter((c) => c.split("=")[1] !== "") // drop deletion cookies
    .join("; ");
}

describe("Pages Router E2E: handleAuth login → callback", () => {
  const originalAppBaseUrl = process.env.APP_BASE_URL;
  const routes = {
    login: "/api/auth/login",
    logout: "/api/auth/logout",
    callback: "/api/auth/callback"
  };

  beforeEach(() => {
    process.env.APP_BASE_URL = DEFAULT.appBaseUrl;
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env.APP_BASE_URL = originalAppBaseUrl;
    vi.restoreAllMocks();
  });

  it("completes a real login → callback round-trip and sets the session cookie", async () => {
    const auth0 = new Auth0Client({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      secret: DEFAULT.secret,
      routes,
      fetch: getMockAuthorizationServer()
    });

    // ---- 1. Login ----------------------------------------------------------
    const loginReq = createMockNextApiRequest(
      `${DEFAULT.appBaseUrl}/api/auth/login`
    );
    const loginRes = createMockNextApiResponse();

    await auth0.handleAuth(loginReq, loginRes.res);

    // Redirect to the authorization server.
    expect(loginRes.res.statusCode).toBe(307);
    const location = loginRes.headers["location"] as string;
    const authorizationUrl = new URL(location);
    expect(authorizationUrl.origin).toBe(`https://${DEFAULT.domain}`);

    const state = authorizationUrl.searchParams.get("state");
    expect(state).not.toBeNull();
    expect(authorizationUrl.searchParams.get("code_challenge")).not.toBeNull();

    // The transaction cookie must have been written onto the response.
    const loginSetCookie = loginRes.headers["set-cookie"];
    expect(loginSetCookie).toBeDefined();
    const cookieHeader = setCookieToCookieHeader(loginSetCookie);
    expect(cookieHeader).toContain(`__txn_${state}`);

    // ---- 2. Callback -------------------------------------------------------
    const callbackReq = createMockNextApiRequest(
      `${DEFAULT.appBaseUrl}/api/auth/callback?code=auth-code-123&state=${state}`,
      {
        // The browser sends the transaction cookie back via the cookie header.
        headers: { cookie: cookieHeader }
      }
    );
    const callbackRes = createMockNextApiResponse();

    await auth0.handleAuth(callbackReq, callbackRes.res);

    // After a successful code exchange, the SDK redirects to returnTo ("/").
    expect(callbackRes.res.statusCode).toBe(307);
    const callbackLocation = callbackRes.headers["location"] as string;
    expect(new URL(callbackLocation).pathname).toBe("/");

    // The session cookie must have been set on the response.
    const callbackSetCookie = callbackRes.headers["set-cookie"];
    expect(callbackSetCookie).toBeDefined();
    const setCookieValues = Array.isArray(callbackSetCookie)
      ? callbackSetCookie
      : [callbackSetCookie];
    expect(setCookieValues.some((c) => c.startsWith("__session"))).toBe(true);
  });
});
