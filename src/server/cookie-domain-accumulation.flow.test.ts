import { NextRequest } from "next/server.js";
import { ResponseCookies } from "@edge-runtime/cookies";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it
} from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { RESPONSE_TYPES, type SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

/**
 * These tests verify the dual-domain cookie deletion behavior that prevents
 * HTTP 431 errors from cookie accumulation.
 *
 * Per RFC 6265, cookies are unique by (name, domain, path). A cookie with
 * Domain=.example.com and one without domain are TWO DIFFERENT cookies.
 * When the SDK deletes cookies, it must delete both variants to prevent accumulation.
 */

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  cookieDomain: ".example.com",
  sub: "test-user-id",
  sid: "test-session-id",
  idToken: "test-id-token",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token"
};

// Mock authorization server metadata
const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"]
};

// MSW handlers
const handlers = [
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  })
];

const server = setupServer(...handlers);

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

async function createSessionCookie(
  session: SessionData,
  secret: string
): Promise<string> {
  const maxAge = 60 * 60; // 1 hour
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  return await encrypt(session, secret, expiration);
}

describe("Cookie Domain Accumulation Prevention", () => {
  let secret: string;
  let transactionStore: TransactionStore;
  let sessionStore: StatelessSessionStore;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  describe("Logout with domain configuration", () => {
    it("should emit both domain and host-only deletion headers when domain is configured", async () => {
      // Create stores with domain configuration
      transactionStore = new TransactionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      sessionStore = new StatelessSessionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        routes: getDefaultRoutes()
      });

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          idToken: DEFAULT.idToken,
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleLogout(request);

      // Get all Set-Cookie headers
      const setCookieHeaders = response.headers.getSetCookie();

      // Find session cookie deletion headers
      const sessionDomainHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") &&
          header.includes(`Domain=${DEFAULT.cookieDomain}`) &&
          header.includes("Max-Age=0")
      );

      const sessionHostOnlyHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") &&
          !header.includes("Domain=") &&
          header.includes("Max-Age=0")
      );

      // Both variants should be present for session cookie
      expect(sessionDomainHeader).toBeDefined();
      expect(sessionHostOnlyHeader).toBeDefined();
    });

    it("should emit only host-only deletion header when no domain is configured", async () => {
      // Create stores without domain configuration
      transactionStore = new TransactionStore({
        secret,
        cookieOptions: {
          path: "/"
        }
      });

      sessionStore = new StatelessSessionStore({
        secret,
        cookieOptions: {
          path: "/"
        }
      });

      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        routes: getDefaultRoutes()
      });

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          idToken: DEFAULT.idToken,
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleLogout(request);

      // Get all Set-Cookie headers
      const setCookieHeaders = response.headers.getSetCookie();

      // Find session cookie deletion headers
      const sessionDeletionHeaders = setCookieHeaders.filter(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );

      // Should have only one deletion header (host-only, no domain)
      expect(sessionDeletionHeaders.length).toBe(1);
      expect(sessionDeletionHeaders[0]).not.toContain("Domain=");
    });
  });

  describe("Transaction cookie cleanup with domain configuration", () => {
    it("should emit dual deletion headers for transaction cookies when domain is configured", async () => {
      transactionStore = new TransactionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      sessionStore = new StatelessSessionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      // Create a transaction cookie
      const resHeaders = new Headers();
      const resCookies = new ResponseCookies(resHeaders);

      const transactionState = {
        codeVerifier: "test-code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: "test-state-123",
        returnTo: "/dashboard",
        nonce: "test-nonce"
      };

      // Save a transaction (this creates a transaction cookie)
      await transactionStore.save(resCookies, transactionState);

      // Now delete it with rawHeaders to test dual-domain deletion
      const deleteHeaders = new Headers();
      const deleteResCookies = new ResponseCookies(deleteHeaders);

      await transactionStore.delete(
        deleteResCookies,
        transactionState.state,
        deleteHeaders
      );

      const setCookieHeaders = deleteHeaders.getSetCookie();

      // Find transaction cookie deletion headers
      const txnDomainHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__txn_test-state-123=") &&
          header.includes(`Domain=${DEFAULT.cookieDomain}`) &&
          header.includes("Max-Age=0")
      );

      const txnHostOnlyHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__txn_test-state-123=") &&
          !header.includes("Domain=") &&
          header.includes("Max-Age=0")
      );

      // Both variants should be present
      expect(txnDomainHeader).toBeDefined();
      expect(txnHostOnlyHeader).toBeDefined();
    });
  });

  describe("Session store delete with rawHeaders", () => {
    it("should emit dual deletion headers when rawHeaders is provided with domain config", async () => {
      sessionStore = new StatelessSessionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      const headers = new Headers();
      const reqHeaders = new Headers();
      reqHeaders.set("cookie", "__session=test-session-value");

      const mockReqCookies = {
        get: (name: string) =>
          name === "__session" ? { value: "test-session-value" } : undefined,
        getAll: () => [{ name: "__session", value: "test-session-value" }],
        set: () => {},
        delete: () => {},
        has: (name: string) => name === "__session"
      };

      const resCookies = new ResponseCookies(headers);

      // Delete session with rawHeaders
      await sessionStore.delete(mockReqCookies as any, resCookies, headers);

      const setCookieHeaders = headers.getSetCookie();

      // Find session cookie deletion headers
      const sessionDomainHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") &&
          header.includes(`Domain=${DEFAULT.cookieDomain}`) &&
          header.includes("Max-Age=0")
      );

      const sessionHostOnlyHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") &&
          !header.includes("Domain=") &&
          header.includes("Max-Age=0")
      );

      // Both variants should be present
      expect(sessionDomainHeader).toBeDefined();
      expect(sessionHostOnlyHeader).toBeDefined();
    });

    it("should emit single deletion header when rawHeaders is not provided", async () => {
      sessionStore = new StatelessSessionStore({
        secret,
        cookieOptions: {
          domain: DEFAULT.cookieDomain,
          path: "/"
        }
      });

      const headers = new Headers();

      const mockReqCookies = {
        get: (name: string) =>
          name === "__session" ? { value: "test-session-value" } : undefined,
        getAll: () => [{ name: "__session", value: "test-session-value" }],
        set: () => {},
        delete: () => {},
        has: (name: string) => name === "__session"
      };

      const resCookies = new ResponseCookies(headers);

      // Delete session WITHOUT rawHeaders (backward compat)
      await sessionStore.delete(mockReqCookies as any, resCookies);

      const setCookieHeaders = headers.getSetCookie();

      // Find session cookie deletion headers
      const sessionDeletionHeaders = setCookieHeaders.filter(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );

      // Should have only one deletion header (with domain)
      expect(sessionDeletionHeaders.length).toBe(1);
      expect(sessionDeletionHeaders[0]).toContain(
        `Domain=${DEFAULT.cookieDomain}`
      );
    });
  });
});
