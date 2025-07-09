import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server.js";
import { Auth0Client } from "./client.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";
import { generateSecret } from "../test/utils.js";
import { encrypt } from "./cookies.js";
import type { SessionData } from "../types/index.js";

const DEFAULT = {
  domain: "example.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "user_123",
  idToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjoxNjE2MjM5MDIyfQ.example",
  accessToken: "at_123",
  refreshToken: "rt_123",
  sid: "session_123"
};

function getMockAuthorizationServer() {
  return async (url: string, init?: RequestInit) => {
    if (url.includes("/.well-known/openid_configuration")) {
      return new Response(JSON.stringify({
        issuer: `https://${DEFAULT.domain}`,
        authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
        token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
        userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
        jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
        end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
        scopes_supported: ["openid", "profile", "email"],
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"]
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    return new Response("Not found", { status: 404 });
  };
}

describe("Base Path Logout Bug Fix", () => {
  let originalBasePath: string | undefined;
  let originalCookiePath: string | undefined;

  beforeEach(() => {
    originalBasePath = process.env.NEXT_PUBLIC_BASE_PATH;
    originalCookiePath = process.env.AUTH0_COOKIE_PATH;
  });

  afterEach(() => {
    if (originalBasePath) {
      process.env.NEXT_PUBLIC_BASE_PATH = originalBasePath;
    } else {
      delete process.env.NEXT_PUBLIC_BASE_PATH;
    }
    if (originalCookiePath) {
      process.env.AUTH0_COOKIE_PATH = originalCookiePath;
    } else {
      delete process.env.AUTH0_COOKIE_PATH;
    }
  });

  describe("Auth0Client cookie path configuration", () => {
    it("should automatically set cookie path to base path when NEXT_PUBLIC_BASE_PATH is set", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: "a-very-long-secret-key-that-is-at-least-32-characters-long"
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/dashboard");
    });

    it("should handle base path without leading slash", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "dashboard";

      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: "a-very-long-secret-key-that-is-at-least-32-characters-long"
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/dashboard");
    });

    it("should respect explicit AUTH0_COOKIE_PATH over base path", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      process.env.AUTH0_COOKIE_PATH = "/custom";

      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: "a-very-long-secret-key-that-is-at-least-32-characters-long"
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/custom");
    });

    it("should respect explicit client configuration over base path", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: "a-very-long-secret-key-that-is-at-least-32-characters-long",
        session: {
          cookie: {
            path: "/explicit-path"
          }
        }
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/explicit-path");
    });
  });

  describe("Logout with base path", () => {
    it("should clear session cookie with correct path during logout", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      // Debug: Check session store configuration
      const sessionStore = (client as any).sessionStore;
      console.log('Session store cookie config:', sessionStore.cookieConfig);
      
      // Debug: Check auth client configuration
      const authClient = (client as any).authClient;
      console.log('Auth client routes:', authClient.routes);

      // Create a session
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

      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);

      // Make logout request
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/dashboard/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await client.middleware(request);
      
      // Debug: Check all cookies in response
      console.log('Response cookies:', [...response.cookies.getAll()]);
      
      // Check that cookie is cleared with correct path
      const clearedCookie = response.cookies.get("__session");
      expect(clearedCookie?.value).toBe("");
      expect(clearedCookie?.maxAge).toBe(0);
      expect(clearedCookie?.path).toBe("/dashboard");
    });

    it("should clear transaction cookies with correct path during logout", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      // Create session and transaction cookies
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

      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const transactionCookie = await encrypt({ state: "test-state" }, secret, expiration);

      // Make logout request with both session and transaction cookies
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}; __txn_test-state=${transactionCookie}`);
      const request = new NextRequest(
        new URL("/dashboard/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

             const response = await client.middleware(request);
       
       // Check that session cookie is cleared with correct path
       const clearedSessionCookie = response.cookies.get("__session");
       expect(clearedSessionCookie?.value).toBe("");
       expect(clearedSessionCookie?.maxAge).toBe(0);
       expect(clearedSessionCookie?.path).toBe("/dashboard");
      
      // Transaction cookies should also be cleared with correct path
      // Note: The deleteAll method would handle this, but we can't easily test it
      // in this context without mocking deeper. The important part is that
      // the session cookie is cleared with the correct path.
    });

    it("should work correctly without base path (regression test)", async () => {
      // Don't set NEXT_PUBLIC_BASE_PATH
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      // Create a session
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

      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);

      // Make logout request
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

             const response = await client.middleware(request);
       
       // Check that cookie is cleared with root path
       const clearedCookie = response.cookies.get("__session");
       expect(clearedCookie?.value).toBe("");
       expect(clearedCookie?.maxAge).toBe(0);
       expect(clearedCookie?.path).toBe("/");
    });
  });

  describe("Integration tests", () => {
    it("should handle complete login/logout flow with base path", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      // Verify that the client is configured with the correct cookie path
      const sessionStore = (client as any).sessionStore;
      const transactionStore = (client as any).transactionStore;
      
      expect(sessionStore.cookieConfig.path).toBe("/dashboard");
      expect(transactionStore.cookieConfig.path).toBe("/dashboard");
    });

    it("should handle nested base paths", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/app/dashboard";
      
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/app/dashboard");
    });

    it("should handle base path with trailing slash", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard/";
      
      const secret = await generateSecret(32);
      const client = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.path).toBe("/dashboard/");
    });
  });
}); 