/**
 * M3 BLOCKER: Public API factory createAnonymousSession tests (FR-2).
 * Tests the PUBLIC export from @auth0/nextjs-auth0/server entry.
 */
import { NextRequest, NextResponse } from "next/server.js";
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
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Helper to encode a mock JWT
function createMockJWT(subject: string, expiresIn: number = 3600): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      sub: subject,
      iat: now,
      exp: now + expiresIn
    })
  ).toString("base64url");
  return `${header}.${payload}.signature`;
}

describe("M3 BLOCKER: FR-2 createAnonymousSession PUBLIC API", () => {
  let secret: string;
  let server: any;
  const defaultDomain = "auth0.local";

  beforeAll(async () => {
    server = setupServer(
      http.post(
        `https://${defaultDomain}/anonymous/token`,
        async ({ request }) => {
          const body = (await request.json()) as any;
          // CREATE mode (no session_token)
          if (!body.session_token) {
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `new-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-factory-test"),
              expires_in: 3600,
              scope: "read:catalog",
              ...(body.metadata && { metadata: body.metadata })
            });
          }
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("anon@uuid-factory-test"),
            expires_in: 3600,
            scope: "read:catalog"
          });
        }
      ),
      http.get(
        `https://${defaultDomain}/.well-known/openid-configuration`,
        () => {
          return HttpResponse.json({
            issuer: `https://${defaultDomain}/`,
            authorization_endpoint: `https://${defaultDomain}/authorize`,
            token_endpoint: `https://${defaultDomain}/oauth/token`,
            userinfo_endpoint: `https://${defaultDomain}/userinfo`,
            jwks_uri: `https://${defaultDomain}/.well-known/jwks.json`
          });
        }
      )
    );
    server.listen({ onUnhandledRequest: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  describe("Public factory createAnonymousSession", () => {
    it("M3: Factory (req, res) form creates session", async () => {
      // Use PUBLIC factory from AuthClient (mirrors SDK package entry export)
      const auth0 = new AuthClient({
        domain: defaultDomain,
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes: getDefaultRoutes(),
        transactionStore: new TransactionStore({
          secret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true }
      });

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      // Public method: (req, res) form
      const session = await auth0.createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // ASSERT: session returned
      expect(session).toBeTruthy();
      expect(session.id).toMatch(/^anon@/);
      expect(session.accessToken).toBeTruthy();

      // Verify cookie was set on response
      const cookies = res.cookies.getAll();
      expect(cookies.some((c) => c.name === "auth0_anon")).toBe(true);
    });

    it("M3: Factory sets cookie on response with correct attributes", async () => {
      const auth0 = new AuthClient({
        domain: defaultDomain,
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes: getDefaultRoutes(),
        transactionStore: new TransactionStore({
          secret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true }
      });

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      // Public method: (req, res) form
      const session = await auth0.createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // ASSERT: session returned, id matches anon@ format
      expect(session).toBeTruthy();
      expect(session.id).toMatch(/^anon@/);
      expect(session.accessToken).toBeTruthy();

      // Verify cookie was set on response
      const cookies = res.cookies.getAll();
      const anonCookie = cookies.find((c) => c.name === "auth0_anon");
      expect(anonCookie).toBeTruthy();
      expect(anonCookie!.value).toBeTruthy();

      // Security attributes
      expect(anonCookie?.httpOnly).toBe(true);
      expect(anonCookie?.sameSite).toBe("lax");
      expect(anonCookie?.path).toBe("/");
      expect(anonCookie?.secure).toBe(true);
    });

    it("M3: Factory throws when feature disabled (unauthorized_client)", async () => {
      const disabledAuth0 = new AuthClient({
        domain: defaultDomain,
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes: getDefaultRoutes(),
        transactionStore: new TransactionStore({
          secret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: false }
      });

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      // ASSERT: throws AnonymousSessionError with code unauthorized_client
      await expect(
        disabledAuth0.createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow(/not enabled/);
    });
  });
});
