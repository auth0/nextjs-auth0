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
import type { AnonymousCookiePayload } from "../types/anonymous-session.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
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

describe("Auth0Client: Anonymous Sessions Routes (a3)", () => {
  let client: AuthClient;
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
              access_token: createMockJWT("anon@uuid-1234"),
              expires_in: 3600,
              scope: "read:catalog",
              ...(body.metadata && { metadata: body.metadata })
            });
          }
          // RENEW mode (has session_token) returns NO session_token
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("anon@uuid-1234"),
            expires_in: 3600,
            metadata: body.metadata,
            scope: "read:catalog"
          });
        }
      ),
      http.post(`https://${defaultDomain}/anonymous/logout`, () => {
        return HttpResponse.json({ ok: true });
      }),
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
    const routes = getDefaultRoutes();
    client = new AuthClient({
      domain: defaultDomain,
      clientId: "test-id",
      clientSecret: "test-secret",
      appBaseUrl: "http://localhost:3000",
      secret,
      routes,
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
  });

  async function createSessionCookie(
    payload: AnonymousCookiePayload,
    secret: string
  ): Promise<string> {
    // Always use far-future JWE expiration so cookie is always decryptable.
    // Logical expiry is evaluated from payload's expires_at field.
    const farFutureExpiration = Math.floor(Date.now() / 1000) + 3600;
    return encrypt(payload, secret, farFutureExpiration);
  }

  describe("handleGetAnonymousSession", () => {
    it("T1.1: GET /auth/anonymous-session returns 204 when no session", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
    });

    it("T1.3: GET returns 200 + session JSON when valid", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-123",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const body = (await res.json()) as any;
      expect(body.id).toMatch(/^anon@/);
      expect(body.accessToken).toBeDefined();
    });

    it("REG-C3: GET response includes renewed cookies in Set-Cookie header when access expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "valid",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredPayload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("auth0_anon");
      expect(setCookie).toContain("HttpOnly");
    });

    it("T8.1: GET returns 404 when feature disabled", async () => {
      const disabledClient = new AuthClient({
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
      const res = await (disabledClient as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(404);
    });

    it("T1-REG: Flow - GET with renewal transfers cookies to response", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredPayload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      // Verify session JSON is present
      const body = (await res.json()) as any;
      expect(body.id).toMatch(/^anon@/);
      // Verify cookies in Set-Cookie
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toBeTruthy();
    });
  });

  // CASCADE-v2 M1: update route removed. Tests deleted (T3.1-T3.6, REG-C3, T3-REG-RECOVERY).

  describe("Create Anonymous Session - Additional Coverage", () => {
    it("T2.5: id shape validation - created session id equals access_token sub claim and matches anon@", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      expect(session.id).toMatch(/^anon@/);
      const jwt = session.accessToken;
      const [, payloadPart] = jwt.split(".");
      const payload = JSON.parse(
        Buffer.from(payloadPart, "base64url").toString()
      );
      expect(session.id).toBe(payload.sub);
    });

    // CASCADE-v2 M2: create accepts metadata
    it("M2-CREATE-MD-1: createAnonymousSession({metadata}) sends metadata in create request body", async () => {
      let capturedBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            capturedBody = await request.json();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `new-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-create-md"),
              expires_in: 3600,
              scope: "read:catalog"
            });
          }
        )
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await (client as any).createAnonymousSession(req.cookies, res.cookies, {
        metadata: { cart: { items: 2 }, prefs: { theme: "dark" } }
      });

      expect(capturedBody).toHaveProperty("metadata");
      expect(capturedBody.metadata).toEqual({
        cart: { items: 2 },
        prefs: { theme: "dark" }
      });
      expect(capturedBody).not.toHaveProperty("session_token");
    });

    it("M2-CREATE-MD-2: createAnonymousSession() no metadata → no metadata field in body", async () => {
      let capturedBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            capturedBody = await request.json();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `new-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-no-md"),
              expires_in: 3600,
              scope: "read:catalog"
            });
          }
        )
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await (client as any).createAnonymousSession(req.cookies, res.cookies);

      expect(capturedBody).not.toHaveProperty("metadata");
    });

    it("M2-CREATE-MD-3a: metadata exactly 1024 UTF-8 bytes → ACCEPTED", async () => {
      // Construct metadata whose JSON.stringify UTF-8 byteLength is EXACTLY 1024
      // JSON format: {"m":"..."} → 8 overhead bytes + payload
      // Need payload of 1024 - 8 = 1016 ASCII chars
      const payload = "x".repeat(1016);
      const metadata = { m: payload };
      const serialized = JSON.stringify(metadata);
      const byteLength = new TextEncoder().encode(serialized).byteLength;

      expect(byteLength).toBe(1024); // Sanity check

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies,
        { metadata }
      );

      expect(session.id).toMatch(/^anon@/);
    });

    it("M2-CREATE-MD-3b: metadata 1025 UTF-8 bytes → REJECTED (metadata_too_large)", async () => {
      // JSON format: {"m":"..."} → 8 overhead + 1017 = 1025 bytes
      const payload = "x".repeat(1017);
      const metadata = { m: payload };
      const serialized = JSON.stringify(metadata);
      const byteLength = new TextEncoder().encode(serialized).byteLength;

      expect(byteLength).toBe(1025); // Sanity check

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata
        })
      ).rejects.toThrow(/metadata.*1KB/i);
    });

    it("M2-CREATE-MD-3c: metadata >1KB throws BEFORE network call (no request issued)", async () => {
      let requestCount = 0;
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, async () => {
          requestCount++;
          return HttpResponse.json({
            token_type: "Bearer",
            session_token: `new-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-1234"),
            expires_in: 3600,
            scope: "read:catalog"
          });
        })
      );

      const largeMetadata = { data: "x".repeat(2000) };
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: largeMetadata
        })
      ).rejects.toThrow(/metadata.*1KB/i);

      // CRITICAL: network call MUST NOT have been made
      expect(requestCount).toBe(0);
    });

    it("M2-CREATE-MD-4: silent recovery (renewal) omits metadata", async () => {
      let recoveryBody: any = null;
      let callCount = 0;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            callCount++;
            const body = (await request.json()) as any;
            if (callCount === 1 && body.session_token) {
              return HttpResponse.json(
                { error: "session_expired" },
                { status: 400 }
              );
            }
            recoveryBody = body;
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `recovery-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-recovery"),
              expires_in: 3600,
              scope: "read:catalog"
            });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "expired-token",
        access_token: createMockJWT("anon@uuid-old", -100),
        expires_at: now - 100,
        metadata: { cart: { qty: 5 } }
      };
      const encrypted = await createSessionCookie(expiredPayload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      expect(recoveryBody).not.toHaveProperty("metadata");
    });
  });

  describe("handleAnonymousLogout", () => {
    it("T4.1: POST /logout clears cookie and returns 200", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleAnonymousLogout(req);

      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("auth0_anon");
      expect(setCookie).toContain("Max-Age=0");
    });

    it("T4.2: POST /logout with no session returns 200 (idempotent)", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST"
        }
      );

      const res = await (client as any).handleAnonymousLogout(req);

      expect(res.status).toBe(200);
    });

    it("T4.3: Called twice is idempotent", async () => {
      const req1 = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST"
        }
      );
      const res1 = await (client as any).handleAnonymousLogout(req1);

      const req2 = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST"
        }
      );
      const res2 = await (client as any).handleAnonymousLogout(req2);

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
    });

    it("T4.4: Auth0 logout call fails (non-5xx) but still clears cookie and returns 200", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/logout`, () => {
          return HttpResponse.json(
            {
              error: "invalid_token"
            },
            { status: 400 }
          );
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleAnonymousLogout(req);

      // Should still return 200 and clear cookie
      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("Max-Age=0");
    });

    it("T4.5: Auth0 logout 5xx throws error (no 5xx swallow)", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/logout`, () => {
          return HttpResponse.json(
            {
              error: "server_error"
            },
            { status: 500 }
          );
        })
      );

      // The route (handleAnonymousLogout) swallows 5xx by design (idempotent),
      // but the network method (anonymousLogoutRequest) should throw.
      await expect(
        (client as any).anonymousLogoutRequest("token")
      ).rejects.toThrow();
    });

    // CASCADE-v2 M3: logout body = {client_id} + clientAuth params (not just {client_id}), session_token NOT in body.
    it("M3-LOGOUT-1: logout request body includes client_id + clientAuth params, session_token NOT in body", async () => {
      let capturedBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/logout`,
          async ({ request }) => {
            capturedBody = await request.json();
            return new HttpResponse(null, { status: 200 });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      await (client as any).handleAnonymousLogout(req);

      expect(capturedBody).toHaveProperty("client_id");
      expect(capturedBody.client_id).toBe("test-id");
      expect(capturedBody).not.toHaveProperty("session_token");
      // clientAuth adds client_secret to body (for client_secret_post mode)
      expect(capturedBody).toHaveProperty("client_secret");
    });

    it("M3-LOGOUT-2: logout with no client_id sends clientAuth params only, session_token NOT in body", async () => {
      let capturedBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/logout`,
          async ({ request }) => {
            capturedBody = await request.json();
            return new HttpResponse(null, { status: 200 });
          }
        )
      );

      // Create client with client_secret but no client_id (server-to-server mode)
      const secretClient = new AuthClient({
        domain: defaultDomain,
        clientId: "",
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

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      await (secretClient as any).handleAnonymousLogout(req);

      // Body = {client_id: ""} + clientAuth params (client_secret)
      expect(capturedBody).toHaveProperty("client_id");
      expect(capturedBody).not.toHaveProperty("session_token");
    });

    it("M3-LOGOUT-3a: logout clears cookie UNCONDITIONALLY on network success (200)", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/logout`, () => {
          return HttpResponse.json({ ok: true }, { status: 200 });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleAnonymousLogout(req);

      // Returns 200 and clears cookie
      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("Max-Age=0");
    });

    it("M3-LOGOUT-3b: logout clears cookie UNCONDITIONALLY on HTTP 500 response", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/logout`, () => {
          return HttpResponse.json({ error: "server_error" }, { status: 500 });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleAnonymousLogout(req);

      // Handler swallows 5xx, returns 200, and clears cookie
      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("Max-Age=0");
    });

    it("REG-Q2: logout clears chunked cookie fragments, not just the base cookie", async () => {
      // Build a payload large enough to be stored as chunks (>4KB encrypted).
      const now = Math.floor(Date.now() / 1000);
      const bigPayload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600,
        metadata: { blob: "x".repeat(6000) }
      };
      // Persist through the SDK so the chunking logic runs and req/res cookies
      // hold the real chunk set (auth0_anon, auth0_anon__0, ...).
      const persistReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const persistRes = new NextResponse();
      await (client as any).persistAnonymousCookie(
        bigPayload,
        persistReq.cookies,
        persistRes.cookies
      );

      const chunkNames = persistRes.cookies
        .getAll()
        .map((c: any) => c.name)
        .filter((n: string) => n.startsWith("auth0_anon"));
      // Sanity: the payload actually chunked.
      expect(chunkNames.length).toBeGreaterThan(1);

      // Rebuild a request carrying every chunk cookie.
      const cookieHeader = persistRes.cookies
        .getAll()
        .filter((c: any) => c.name.startsWith("auth0_anon"))
        .map((c: any) => `${c.name}=${c.value}`)
        .join("; ");
      const logoutReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        { method: "POST", headers: { cookie: cookieHeader } }
      );

      const res = await (client as any).handleAnonymousLogout(logoutReq);
      expect(res.status).toBe(200);

      // Every chunk cookie must be cleared (Max-Age=0), not only the base name.
      const cleared = res.cookies
        .getAll()
        .filter((c: any) => c.name.startsWith("auth0_anon"));
      const clearedNames = cleared.map((c: any) => c.name);
      for (const name of chunkNames) {
        expect(clearedNames).toContain(name);
      }
      for (const c of cleared) {
        expect(c.maxAge).toBe(0);
      }
    });
  });

  describe("handleGetAnonymousSession - Additional Coverage", () => {
    it("T1.2: malformed cookie (invalid JWE) returns 204 with no throw, no network call", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: "auth0_anon=not-valid-jwe-format" }
        }
      );

      // MSW with onUnhandledRequest: 'error' will fail the test if any network call is made
      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
    });

    it("T1.6: access expired, read-only context (no writable cookies) returns decrypted session as-is", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredAccessPayload: AnonymousCookiePayload = {
        session_token: "valid-session",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredAccessPayload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      // Call the internal method with only reqCookies (simulating read-only context like Server Component)
      const session = await (client as any).resolveAnonymousSession(
        req.cookies,
        undefined
      );

      // Should return the decrypted session as-is, without attempting renewal
      expect(session).not.toBeNull();
      expect(session?.id).toMatch(/^anon@/);
    });

    it("T1.7: authorization server returns server_error on renewal → returns 500 error response", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, async () => {
          return HttpResponse.json({ error: "server_error" }, { status: 500 });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const expiredAccessPayload: AnonymousCookiePayload = {
        session_token: "valid-session",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredAccessPayload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      // Handler catches the error and returns error response
      expect(res.status).toBe(500);
      const body = (await res.json()) as any;
      expect(body.error).toBe("server_error");
    });
  });

  // CASCADE-v2 M1: "Metadata Update - Additional Coverage" describe block removed (T3.2, T3.6).

  describe("Create Anonymous Session - Additional Coverage", () => {
    it("T2.5: id shape validation - created session id equals access_token sub claim and matches anon@", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // Verify id matches anon@ prefix
      expect(session.id).toMatch(/^anon@/);

      // STRENGTHENED: Decode the returned access_token and verify id === sub claim
      const parts = session.accessToken.split(".");
      expect(parts).toHaveLength(3);

      const payloadStr = Buffer.from(parts[1], "base64url").toString();
      const payload = JSON.parse(payloadStr);
      const subClaim = payload.sub;

      // Critical: the session.id MUST come from JWT sub claim, not be hardcoded
      expect(session.id).toBe(subClaim);
      expect(subClaim).toMatch(/^anon@/);
    });

    it("T2.6: create response missing session_token → throws AnonymousSessionError", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, async () => {
          return HttpResponse.json({
            token_type: "Bearer",
            // Missing session_token
            access_token: createMockJWT("anon@uuid-1234"),
            expires_in: 3600,
            scope: "read:catalog"
          });
        })
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow();
    });

    it("T2.7: network error on /anonymous/token → throws AnonymousSessionError", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, async () => {
          return HttpResponse.json(
            { error: "internal_error" },
            { status: 500 }
          );
        })
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow();
    });
  });

  describe("Configuration Gating - Additional Coverage", () => {
    it("T8.5: feature disabled → getAnonymousSession returns null, no network call, no error", async () => {
      const disabledClient = new AuthClient({
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

      // Should return null (or be unreachable), no network call
      const session = await (disabledClient as any).getAnonymousSession(req);

      // When disabled, getAnonymousSession should return null
      expect(session).toBeNull();
    });

    it("T8.3: cookie name override → encrypted state stored under custom name", async () => {
      const customCookieName = "my_custom_anon_cookie";
      const customClient = new AuthClient({
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
        anonymousSession: { enabled: true, cookie: { name: customCookieName } }
      });

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await (customClient as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // Check that the custom cookie name was used
      const cookies = res.cookies.getAll();
      const customNameCookie = cookies.find((c: any) =>
        c.name.startsWith(customCookieName)
      );
      expect(customNameCookie).toBeDefined();
    });
  });

  describe("createAnonymousSession (public method)", () => {
    it("REG-Q1: throws unauthorized_client when the feature is disabled (no network call)", async () => {
      const disabledClient = new AuthClient({
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

      await expect(
        (disabledClient as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toMatchObject({ code: "unauthorized_client" });
    });
  });

  describe("GUARDING TEST: C1 - Route Dispatch via handler() PUBLIC entry point", () => {
    it("C1: GET /auth/anonymous-session via handler() reaches handleGetAnonymousSession, returns 204 or 200", async () => {
      const getReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        { method: "GET" }
      );

      const res = await (client as any).handler(getReq);

      expect(res).toBeInstanceOf(NextResponse);
      // MUST be exactly 204 (empty body): only handleGetAnonymousSession returns
      // 204 for a no-cookie request. If C1 route defaults were missing, dispatch
      // would fall through to the default handler (NextResponse.next(), status 200),
      // so asserting 204 specifically guards the route-match regression.
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
    });

    // CASCADE-v2 M1: C1 update dispatch test removed (update route gone).

    it("C1: POST /auth/anonymous-session/logout via handler() reaches handleAnonymousLogout, returns 200 with Max-Age=0", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);

      const logoutReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session/logout"),
        {
          method: "POST",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handler(logoutReq);

      expect(res).toBeInstanceOf(NextResponse);
      expect(res.status).toBe(200);
      // Check either set-cookie header or getSetCookie() array
      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBeGreaterThan(0);
      const hasMaxAge0 = setCookies.some((c: string) =>
        c.includes("Max-Age=0")
      );
      expect(hasMaxAge0).toBe(true);
    });
  });

  describe("GUARDING TEST: M1 - session_token retention on renewal", () => {
    it("M1: session_token preserved during GET renewal (expired access, valid session)", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "S1-original",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(payload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toBeTruthy();

      // Extract and decrypt the renewed cookie
      const cookieMatch = setCookie?.match(/auth0_anon=([^;]+)/);
      expect(cookieMatch).toBeTruthy();
      const renewedCookieValue = cookieMatch![1];
      const decrypted = await (
        await import("../server/cookies.js")
      ).decrypt<AnonymousCookiePayload>(renewedCookieValue, secret);

      // CRITICAL: session_token must be preserved from the original cookie
      expect(decrypted).not.toBeNull();
      expect(decrypted?.payload.session_token).toBe("S1-original");
    });

    // CASCADE-v2 M1: M1 update-route session_token retention test removed (update route gone).
  });

  describe("GUARDING TEST: M4 - Metadata UTF-8 byte cap (not string length cap)", () => {
    it("M4: Metadata with multibyte chars <1024 string length but >1024 UTF-8 bytes is REJECTED at CREATE", async () => {
      // Each emoji is 4 UTF-8 bytes but counts as 2 UTF-16 code units (JavaScript string length)
      // 260 emojis = 520 UTF-16 units + JSON overhead ~15 bytes = ~535 string.length
      // But 260 * 4 UTF-8 bytes + overhead = 1050+ UTF-8 bytes (exceeds 1024)
      const multibyteMetadata = {
        data: "😀".repeat(260)
      };
      const serialized = JSON.stringify(multibyteMetadata);
      const stringLength = serialized.length;
      const byteLength = new TextEncoder().encode(serialized).length;

      // Sanity checks for test validity
      expect(stringLength).toBeLessThanOrEqual(1024);
      expect(byteLength).toBeGreaterThan(1024);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      // CASCADE-v2 M2: metadata_too_large now at CREATE, not update
      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: multibyteMetadata
        })
      ).rejects.toThrow(/metadata.*1KB/i);
    });

    it("M4: Metadata with ASCII chars under 1024 UTF-8 bytes is ACCEPTED at CREATE", async () => {
      // Pure ASCII: string length = UTF-8 byte length
      // Use 1000 bytes worth of ASCII to stay safely under cap
      const asciiMetadata = {
        data: "x".repeat(1000)
      };
      const serialized = JSON.stringify(asciiMetadata);
      const stringLength = serialized.length;
      const byteLength = new TextEncoder().encode(serialized).length;

      // Both should be ≤1024 for ASCII
      expect(stringLength).toBeLessThanOrEqual(1024);
      expect(byteLength).toBeLessThanOrEqual(1024);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      // CASCADE-v2 M2: metadata validation now at CREATE
      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies,
        { metadata: asciiMetadata }
      );

      expect(session.id).toMatch(/^anon@/);
      expect(session.metadata).toEqual(asciiMetadata);
    });
  });

  describe("GUARDING TEST: M2/M3 - HTTP status mapping per error code (§3.C7)", () => {
    it("M2/M3: invalid_client (401) error returns 401 status", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json(
            { error: "invalid_client" },
            { status: 401 }
          );
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(payload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(401);
      const body = (await res.json()) as any;
      expect(body.error).toBe("invalid_client");
    });

    it("M2/M3: feature_not_enabled (403) error returns 403 status", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json(
            { error: "feature_not_enabled" },
            { status: 403 }
          );
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(payload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(403);
      const body = (await res.json()) as any;
      expect(body.error).toBe("feature_not_enabled");
    });

    it("M2/M3: unauthorized_client (403) error returns 403 status", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json(
            { error: "unauthorized_client" },
            { status: 403 }
          );
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(payload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(403);
      const body = (await res.json()) as any;
      expect(body.error).toBe("unauthorized_client");
    });

    it("M2/M3: server_error (500) error returns 500 status", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json({ error: "server_error" }, { status: 500 });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: createMockJWT("anon@uuid-1234", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(payload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          method: "GET",
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(500);
      const body = (await res.json()) as any;
      expect(body.error).toBe("server_error");
    });
  });
});
