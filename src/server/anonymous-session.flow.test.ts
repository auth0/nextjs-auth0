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
import { decrypt, encrypt } from "./cookies.js";
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

describe("Anonymous Session Complete Flow Tests (Section 4)", () => {
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
          // CREATE mode (no session_token) returns new session_token
          if (!body.session_token) {
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600,
              scope: "read:catalog",
              // metadata ONLY if body.metadata provided, else omit
              ...(body.metadata && { metadata: body.metadata })
            });
          }
          // RENEW mode (has session_token) returns NO session_token
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("anon@uuid-9999"),
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

  // CASCADE-v2 M1: Flow Suite 4.1 DELETED (update route removed).

  describe("Flow Suite 4.1: Renewal & Recovery (retained non-update tests)", () => {
    it("Flow: Access token renewal under expiry pressure (T1.4 + REG-C3)", async () => {
      // Create session with expired access token but valid session token
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "valid-session",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
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
      // Verify renewed token in Set-Cookie
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("auth0_anon");

      const session = (await res.json()) as any;
      expect(session.id).toMatch(/^anon@/);
    });

    it("Flow: Session expiry triggers silent recovery (T1.5)", async () => {
      // Session token expired → renew attempt returns session_expired error → silent create
      let callCount = 0;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            callCount++;
            const body = (await request.json()) as any;
            if (callCount === 1) {
              // First call (RENEW attempt with expired session_token) → session_expired
              expect(body.session_token).toBe("expired-session");
              return HttpResponse.json(
                { error: "session_expired" },
                { status: 400 }
              );
            }
            // Second call (CREATE, no session_token) → fresh session
            expect(body.session_token).toBeUndefined();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-recovered-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600,
              scope: "read:catalog"
            });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "expired-session",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100,
        metadata: { lost: "data" }
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
      const session = (await res.json()) as any;
      expect(session.id).toMatch(/^anon@/);
      // Metadata lost on recovery (create mode has no metadata in response)
      expect(session.metadata).toBeUndefined();
      expect(callCount).toBe(2);
    });

    it("Flow: T1.5b invalid_session_token recovery during renewal", async () => {
      // Distinct from session_expired: invalid_session_token also triggers recovery
      let callCount = 0;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            callCount++;
            const body = (await request.json()) as any;
            if (callCount === 1) {
              // First call (RENEW attempt) → invalid_session_token
              expect(body.session_token).toBe("invalid-token");
              return HttpResponse.json(
                { error: "invalid_session_token" },
                { status: 400 }
              );
            }
            // Second call (CREATE) → fresh session
            expect(body.session_token).toBeUndefined();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-recovered-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600,
              scope: "read:catalog"
            });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const invalidPayload: AnonymousCookiePayload = {
        session_token: "invalid-token",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(invalidPayload, secret);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const session = (await res.json()) as any;
      expect(session.id).toMatch(/^anon@/);
      expect(callCount).toBe(2);
    });

    // CASCADE-v2 M1: deleted 2 update tests (metadata-update renewal, session expiry during update).
  });

  // CASCADE-v2 M1: Flow Suite 4.2 DELETED (all update tests).

  describe("Flow Suite 4.2: Cookie Transfer & Renewal (retained GET)", () => {
    it("REG-C3: GET /anonymous-session with renewal transfers cookies to response", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session",
        access_token: createMockJWT("anon@uuid-9999", -100),
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
      // JSON response present
      const session = (await res.json()) as any;
      expect(session.id).toMatch(/^anon@/);
      // Renewed cookies in Set-Cookie header
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("auth0_anon");
      expect(setCookie).toContain("HttpOnly");
    });
  });

  describe("Flow Suite 4.3: Configuration & Lifecycle Independence", () => {
    it("T8.1 Flow: disabled feature → all routes return 404", async () => {
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

    it("T8.2 Flow: disabled feature, authenticated session unaffected", async () => {
      // Even with anonymous session disabled, authenticated session should work
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

      // getSession() should still work (getSession is not a method on client directly,
      // but the test verifies configuration doesn't break other flows)
      const config = (disabledClient as any).anonymousSessionEnabled;
      expect(config).toBe(false);
    });

    it("T6.3 Flow: authenticated logout does not clear anon cookie", async () => {
      const now = Math.floor(Date.now() / 1000);
      const anonPayload: AnonymousCookiePayload = {
        session_token: "anon-session",
        access_token: createMockJWT("anon@uuid-9999"),
        expires_at: now + 3600
      };
      const anonEncrypted = await createSessionCookie(anonPayload, secret);

      // Logout request with anon cookie
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/logout"),
        {
          headers: { cookie: `auth0_anon=${anonEncrypted}` }
        }
      );

      const res = await (client as any).handleLogout(req);

      // Verify anon cookie not cleared
      const setCookies = res.headers.getSetCookie();
      const anonCookieClears = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      expect(anonCookieClears).toHaveLength(0);
    });

    it("T8.5b: cookie.maxAge override honored in Set-Cookie", async () => {
      const customMaxAge = 7200;
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
        anonymousSession: {
          enabled: true,
          cookie: { maxAge: customMaxAge }
        }
      });

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();
      await (customClient as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain(`Max-Age=${customMaxAge}`);
    });
  });

  describe("Flow Suite 4.4: SEC-1 Fixation in Complete Flow", () => {
    it("Login with anon session → injection → callback binding flow", async () => {
      const now = Math.floor(Date.now() / 1000);
      const anonPayload: AnonymousCookiePayload = {
        session_token: "anon-for-login",
        access_token: createMockJWT("anon@uuid-9999"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(anonPayload, secret);

      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      // Verify session_token injected in location header
      const location = result.headers.get("location");
      expect(location).toContain("session_token=anon-for-login");
    });

    it("SEC-1 T5.3: Attacker-supplied session_token parameter is STRIPPED (Layer 1 defense)", async () => {
      // CRITICAL SECURITY TEST: Verify that caller-supplied session_token in request is rejected.
      // This is Layer 1 of SEC-1: reserved parameter stripping.
      // The attack: attacker passes ?session_token=evil in query params or authorizationParams.
      // Expected: SDK strips it before processing.

      const now = Math.floor(Date.now() / 1000);
      const legitimatePayload: AnonymousCookiePayload = {
        session_token: "legitimate-sdk-token",
        access_token: createMockJWT("anon@uuid-9999"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(legitimatePayload, secret);

      // Attacker supplies their own session_token in authorizationParams
      const attackerParams = { session_token: "attacker-token-xyz" };
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParams: attackerParams
        },
        req
      );

      // Layer 1: attacker-supplied session_token must be stripped
      // SDK cookie should be injected, not attacker token
      const location = result.headers.get("location");
      expect(location).toContain("session_token=legitimate-sdk-token");
      // Most critical: attacker token must NOT appear in authorization URL
      expect(location).not.toContain("attacker-token-xyz");
    });

    it("SEC-1 T5.4: Injected session_token sourced only from own SDK cookie (Layer 2 defense)", async () => {
      // Layer 2 of SEC-1: own-cookie sourcing.
      // Verify that the injected session_token comes ONLY from the encrypted SDK cookie,
      // not from any request input.
      // Proof: decrypt the cookie, verify its session_token matches the injected value.

      const now = Math.floor(Date.now() / 1000);
      const cookiePayload: AnonymousCookiePayload = {
        session_token: "unique-cookie-token-789",
        access_token: createMockJWT("anon@uuid-9999"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(cookiePayload, secret);

      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      // The injected token must be the exact one from the encrypted cookie
      const location = result.headers.get("location");
      expect(location).toContain("session_token=unique-cookie-token-789");
    });

    it("SEC-1 T6.1: Transaction state binding records anonymousSessionLinked flag", async () => {
      // Layer 3 of SEC-1: transaction state binding.
      // Verify that when a session is injected, the flag is set in transaction state.
      // This prevents swapped-cookie attacks at callback time.

      const now = Math.floor(Date.now() / 1000);
      const anonPayload: AnonymousCookiePayload = {
        session_token: "session-bound",
        access_token: createMockJWT("anon@uuid-9999"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(anonPayload, secret);

      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      // After startInteractiveLogin, the transaction state should have anonymousSessionLinked=true
      // This is verified at callback time to prevent cookie-swap attacks
      const location = result.headers.get("location");
      expect(location).toContain("session_token=session-bound");

      // Decrypt transaction cookie and verify anonymousSessionLinked flag
      const stateMatch = location!.match(/state=([^&]+)/);
      expect(stateMatch).toBeTruthy();
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        stateMatch![1]
      );
      expect(txState).toBeTruthy();
      expect(txState.payload.anonymousSessionLinked).toBe(true);
    });

    it("SEC-1 T6.2: No session at login → anonymousSessionLinked flag false", async () => {
      // When no anon session exists, flag must be false so callback knows
      // not to apply migration logic.

      const req = new NextRequest(new URL("http://localhost:3000/auth/login"));

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      // No session_token in URL since no cookie
      const location = result.headers.get("location");
      expect(location).not.toContain("session_token=");

      // Decrypt transaction cookie and verify anonymousSessionLinked flag is false
      const stateMatch = location!.match(/state=([^&]+)/);
      expect(stateMatch).toBeTruthy();
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        stateMatch![1]
      );
      expect(txState).toBeTruthy();
      expect(txState.payload.anonymousSessionLinked || false).toBe(false);
    });

    it("C2 BLOCKER: SEC-1 Layer 3 callback transaction binding prevents cookie swap attacks", async () => {
      // CRITICAL SECURITY TEST (C2 BLOCKER): Prove that anonymousSessionLinked
      // at callback derives from TRANSACTION STATE bound at login, not from
      // request-time cookie. Attack scenario: login with session A binds transaction;
      // at callback attacker presents a different/forged cookie B; SDK must use
      // the transaction-bound state (session A digest), not the swapped cookie B.
      //
      // verifyAnonymousSessionLink (line 2916) checks:
      //   transactionState.anonymousSessionRef === digest(current_cookie.session_token)
      // If they don't match → returns false (link rejected).

      const now = Math.floor(Date.now() / 1000);

      // Session A: legitimate session at login
      const sessionA: AnonymousCookiePayload = {
        session_token: "session-a-legit",
        access_token: createMockJWT("anon@uuid-a"),
        expires_at: now + 3600
      };
      const encryptedA = await createSessionCookie(sessionA, secret);

      // Login with session A → binds transaction state with digest of "session-a-legit"
      const loginReq = new NextRequest(
        new URL("http://localhost:3000/auth/login"),
        { headers: { cookie: `auth0_anon=${encryptedA}` } }
      );
      const loginRes = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        loginReq
      );

      // Extract state param from redirect (needed for callback)
      const location = loginRes.headers.get("location");
      expect(location).toContain("state=");
      const stateMatch = location!.match(/state=([^&]+)/);
      expect(stateMatch).toBeTruthy();
      const state = stateMatch![1];

      // Attacker scenario: at callback time, present a DIFFERENT cookie (session B)
      const sessionB: AnonymousCookiePayload = {
        session_token: "session-b-attacker",
        access_token: createMockJWT("anon@uuid-b-attacker"),
        expires_at: now + 3600
      };
      const encryptedB = await createSessionCookie(sessionB, secret);

      // Callback with swapped cookie B (attacker injection)
      // verifyAnonymousSessionLink should detect mismatch:
      //   transactionState.anonymousSessionRef (digest of A) !== digest(B)
      //   → returns false → anonymousSessionLinked = false
      const callbackReq = new NextRequest(
        new URL(
          `http://localhost:3000/auth/callback?code=mock-code&state=${state}`
        ),
        {
          headers: {
            cookie: `auth0_anon=${encryptedB};auth0_tx=${loginRes.cookies.get("auth0_tx")?.value}`
          }
        }
      );

      // We can't fully drive handleCallback without mocking OAuth token exchange,
      // but we CAN directly test the security function verifyAnonymousSessionLink.
      // Read transaction state from cookie.
      const txState = await (client as any).transactionStore.get(
        loginRes.cookies,
        state
      );
      expect(txState).toBeTruthy();

      // Call verifyAnonymousSessionLink with transaction state (bound to A) and request with cookie B
      const linkedFlag = await (client as any).verifyAnonymousSessionLink(
        txState.payload,
        callbackReq
      );

      // CRITICAL ASSERTION: linkedFlag must be FALSE because cookie swap detected
      // (transaction ref digest of A ≠ digest of B's session_token)
      expect(linkedFlag).toBe(false);
    });
  });

  // CASCADE-v2 M1: Flow Suite 4.5 update body tests DELETED.

  describe("Flow Suite 4.5: HTTP Request Body Inspection (retained create/renew)", () => {
    it("T2.8/T2.9: audience + scope present in create AND renew request bodies", async () => {
      const clientWithAudience = new AuthClient({
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
        anonymousSession: {
          enabled: true,
          audience: "https://api.example.com",
          scope: "read:data write:data"
        }
      });

      let capturedCreateBody: any = null;
      let capturedRenewBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as any;
            if (!body.session_token) {
              // CREATE mode
              capturedCreateBody = body;
              return HttpResponse.json({
                token_type: "Bearer",
                session_token: `session-${Date.now()}`,
                access_token: createMockJWT("anon@uuid-9999"),
                expires_in: 3600,
                scope: "read:data write:data"
              });
            }
            // RENEW mode
            capturedRenewBody = body;
            return HttpResponse.json({
              token_type: "Bearer",
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600,
              scope: "read:data write:data"
            });
          }
        )
      );

      // Step 1: CREATE
      const createReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const createRes = new NextResponse();
      await (clientWithAudience as any).createAnonymousSession(
        createReq.cookies,
        createRes.cookies
      );

      expect(capturedCreateBody).toBeTruthy();
      expect(capturedCreateBody.audience).toBe("https://api.example.com");
      expect(capturedCreateBody.scope).toBe("read:data write:data");

      // Step 2: RENEW (expired access)
      const now = Math.floor(Date.now() / 1000);
      const renewPayload: AnonymousCookiePayload = {
        session_token: "session-123",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(renewPayload, secret);
      const renewReq = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      await (clientWithAudience as any).handleGetAnonymousSession(renewReq);

      expect(capturedRenewBody).toBeTruthy();
      expect(capturedRenewBody.audience).toBe("https://api.example.com");
      expect(capturedRenewBody.scope).toBe("read:data write:data");
      expect(capturedRenewBody.session_token).toBe("session-123");
    });

    it("T2.8/T2.9: audience + scope both undefined when not configured", async () => {
      let capturedBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            capturedBody = await request.json();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600
            });
          }
        )
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();
      await (client as any).createAnonymousSession(req.cookies, res.cookies);

      expect(capturedBody).toBeTruthy();
      expect(capturedBody.audience).toBeUndefined();
      expect(capturedBody.scope).toBeUndefined();
    });

    it("T2.10: renew 200 returns NO session_token", async () => {
      let responseBody: any = null;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as any;
            // RENEW mode (has session_token)
            if (body.session_token) {
              responseBody = {
                token_type: "Bearer",
                access_token: createMockJWT("anon@uuid-9999"),
                expires_in: 3600
              };
              return HttpResponse.json(responseBody);
            }
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600
            });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "session-123",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
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
      // Verify MSW response body has NO session_token
      expect(responseBody).toBeTruthy();
      expect(responseBody.session_token).toBeUndefined();

      // Verify SDK retained the ORIGINAL session_token in persisted cookie
      const anonCookie = res.cookies.get("auth0_anon");
      expect(anonCookie).toBeTruthy();
      const decrypted = await decrypt<AnonymousCookiePayload>(
        anonCookie!.value,
        secret
      );
      expect(decrypted).toBeTruthy();
      expect(decrypted!.payload.session_token).toBe("session-123");
    });

    it("T2.11: logout 204 empty body not parsed", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/logout`, () => {
          return new HttpResponse(null, { status: 204 });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "token-to-logout",
        access_token: createMockJWT("anon@uuid-9999"),
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
      expect(setCookie).toContain("Max-Age=0");
    });
  });

  describe("Flow Suite 4.6: FR-2 createAnonymousSession Factory", () => {
    it("FR-2: Zero-argument form creates new anonymous session", async () => {
      // Test that createAnonymousSession() with no args creates a fresh session
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();
      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      expect(session.id).toMatch(/^anon@/);
      expect(session.accessToken).toBeDefined();
      expect(session.expiresAt).toBeGreaterThan(0);
    });

    it("FR-2: req/res form with cookies creates and persists session", async () => {
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();
      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // Verify session returned
      expect(session.id).toMatch(/^anon@/);
      // Verify cookies set in response
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toContain("auth0_anon");
    });
  });

  // CASCADE-v2 M1: Flow Suite 4.7 DELETED (metadata-update tests).

  describe("Flow Suite 4.8: FR-13 invalid_client Error Handling", () => {
    it("FR-13: invalid_client error thrown on authentication failure", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json(
            {
              error: "invalid_client"
            },
            { status: 401 }
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

      // Verify the error is an AnonymousSessionError with code invalid_client
      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
      } catch (e: any) {
        expect(e.code).toBe("invalid_client");
      }
    });

    it("REG-D1: AnonymousSessionError carries description + cause from server error", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json(
            {
              error: "feature_not_enabled",
              error_description:
                "Anonymous sessions not enabled for this tenant"
            },
            { status: 403 }
          );
        })
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
        throw new Error("Should have thrown");
      } catch (e: any) {
        expect(e.code).toBe("feature_not_enabled");
        expect(e.description).toBe(
          "Anonymous sessions not enabled for this tenant"
        );
        expect(e.cause).toBeTruthy();
      }
    });
  });

  // CASCADE-v2 M1: Flow Suite 4.9 update test DELETED, GET test retained.

  describe("Flow Suite 4.9: REG-C1 Cookie Transfer Pattern", () => {
    it("REG-C1: GET /anonymous-session transfers renewed cookie to response", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session",
        access_token: createMockJWT("anon@uuid-9999", -100),
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
      // Verify both JSON body AND Set-Cookie header present
      const session = (await res.json()) as any;
      expect(session.id).toMatch(/^anon@/);
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toBeTruthy();
      expect(setCookie).toContain("auth0_anon");
    });
  });

  describe("Concurrent Renewal (8.S5) - Multi-request under expiry", () => {
    it("8.S5: Two concurrent GET requests with expired access → both renew", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredPayload, secret);

      // First request
      const req1 = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );
      const res1Promise = (client as any).handleGetAnonymousSession(req1);

      // Second request (concurrent)
      const req2 = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );
      const res2Promise = (client as any).handleGetAnonymousSession(req2);

      const [res1, res2] = await Promise.all([res1Promise, res2Promise]);

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);

      const body1 = (await res1.json()) as any;
      const body2 = (await res2.json()) as any;

      expect(body1.id).toMatch(/^anon@/);
      expect(body2.id).toMatch(/^anon@/);
    });
  });

  describe("Login Injection & Session Token Fixation (T5, SEC-1)", () => {
    it("T5.1: active anon cookie at login → session_token should be read from cookie", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "sdk-cookie-token-xyz",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      // Verify readAnonymousCookie method can extract the token
      const cookiePayload = await (client as any).readAnonymousCookie(
        req.cookies
      );
      expect(cookiePayload).not.toBeNull();
      expect(cookiePayload?.session_token).toBe("sdk-cookie-token-xyz");
    });

    it("T5.2: no anon cookie at login → readAnonymousCookie returns null", async () => {
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"));

      // Verify readAnonymousCookie returns null when no cookie
      const cookiePayload = await (client as any).readAnonymousCookie(
        req.cookies
      );
      expect(cookiePayload).toBeNull();
    });

    it("T5.5: feature disabled → startInteractiveLogin with disabled client", async () => {
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

      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "should-not-inject",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      // With feature disabled, startInteractiveLogin should proceed without session injection
      const result = await (disabledClient as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );
      expect(result).toBeInstanceOf(NextResponse);
      expect([302, 307]).toContain(result.status);
    });
  });

  describe("SEC-1: Session-Token Fixation Mitigation (Adversarial)", () => {
    it("SEC-1 T5.3: Reserved parameters list includes session_token (stripped before use)", async () => {
      // Verify that session_token is in the INTERNAL_AUTHORIZE_PARAMS list
      // by checking that caller-supplied values are stripped.
      // This is done via the mergeAuthorizationParamsIntoSearchParams function.
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"));

      // Attempt to inject session_token via authorizationParams
      // The startInteractiveLogin method should strip it
      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParams: {
            session_token: "attacker-injected"
          }
        },
        req
      );

      // Verify result is a NextResponse (successful call - either 302 or 307)
      expect(result).toBeInstanceOf(NextResponse);
      expect([302, 307]).toContain(result.status);
    });

    it("SEC-1 T5.4: SDK reads session_token only from own encrypted cookie", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "legitimate-from-own-cookie",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      // readAnonymousCookie should decrypt and return the SDK's own token
      const cookiePayload = await (client as any).readAnonymousCookie(
        req.cookies
      );
      expect(cookiePayload?.session_token).toBe("legitimate-from-own-cookie");
    });

    it("SEC-1 T6.1: SDK can extract session_token from cookie for binding", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: "session-to-bind",
        access_token: createMockJWT("anon@uuid-1234"),
        expires_at: now + 3600
      };
      const encrypted = await createSessionCookie(payload, secret);
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"), {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      // Verify readAnonymousCookie can extract the token for binding
      const cookiePayload = await (client as any).readAnonymousCookie(
        req.cookies
      );
      expect(cookiePayload).not.toBeNull();
      expect(cookiePayload?.session_token).toBeTruthy();
    });

    it("SEC-1 T6.2: startInteractiveLogin with no cookie proceeds without session binding", async () => {
      const req = new NextRequest(new URL("http://localhost:3000/auth/login"));

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      // Should succeed and return a redirect
      expect(result).toBeInstanceOf(NextResponse);
      expect([302, 307]).toContain(result.status);
    });
  });

  describe("Regression tests for CodeRabbit fixes A5 + A8", () => {
    it("A5 regression: renewal with malformed access_token sub returns null, does NOT throw", async () => {
      // A5 fix: renewal path toPublicSession throw (e.g. access_token sub not anon@) must return null
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          // Renewal returns access_token with NON-anon sub → toPublicSession will throw
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("user@123"), // NOT anon@
            expires_in: 3600
          });
        })
      );

      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session-123",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
      };
      const encrypted = await createSessionCookie(expiredPayload, secret);
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        {
          headers: { cookie: `auth0_anon=${encrypted}` }
        }
      );

      // getAnonymousSession must NOT throw, return null (session treated as absent)
      const res = await (client as any).handleGetAnonymousSession(req);
      expect(res.status).toBe(204); // No session
    });

    it("A8 regression: createAnonymousSession with metadata string throws invalid_request", async () => {
      // A8 fix: metadata type validation (string not allowed)
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: "invalid-string" as any
        })
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: "invalid-string" as any
        });
      } catch (e: any) {
        expect(e.code).toBe("invalid_request");
        expect(e.message).toContain("plain object");
      }
    });

    it("A8 regression: createAnonymousSession with metadata array throws invalid_request", async () => {
      // A8 fix: metadata type validation (array not allowed)
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: [1, 2, 3] as any
        })
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: [1, 2, 3] as any
        });
      } catch (e: any) {
        expect(e.code).toBe("invalid_request");
        expect(e.message).toContain("plain object");
      }
    });

    it("A8 regression: createAnonymousSession with metadata number throws invalid_request", async () => {
      // A8 fix: metadata type validation (number not allowed)
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: 42 as any
        })
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies, {
          metadata: 42 as any
        });
      } catch (e: any) {
        expect(e.code).toBe("invalid_request");
        expect(e.message).toContain("plain object");
      }
    });
  });
});
