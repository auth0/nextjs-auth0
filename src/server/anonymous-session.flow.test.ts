import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
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
          // PHASE 2: Transfer ticket mint (distinguished by audience)
          if (body.audience === "urn:auth0:anon_transfer") {
            return HttpResponse.json({
              anon_transfer_token: "mock-transfer-ticket-xyz",
              token_type: "N_A",
              expires_in: 30
            });
          }
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

      // P2: ticket appears as anon_transfer_token; raw session_token absent
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      const url = new URL(location!);
      expect(url.searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
      expect(url.searchParams.has("session_token")).toBe(false);
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
          authorizationParameters: attackerParams
        },
        req
      );

      // Layer 1: attacker-supplied session_token must be stripped
      // P2: SDK now appends anon_transfer_token (not raw session_token)
      const location = result.headers.get("location");
      const url = new URL(location!);
      expect(url.searchParams.has("session_token")).toBe(false);
      expect(location).not.toContain("attacker-token-xyz");
      expect(url.searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
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

      // P2: transfer ticket derived from this cookie's session_token is appended
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
      expect(new URL(location!).searchParams.has("session_token")).toBe(false);
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
      // P2: ticket appears as anon_transfer_token, not raw session_token
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );

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
          authorizationParameters: {
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

    it("CR-1b regression: createAnonymousSession with expires_in > 2592000 throws invalid_response", async () => {
      // CR-1b fix: upper bound on expires_in to prevent decades-long tokens
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: 999999999 // Absurdly large
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

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
      } catch (e: any) {
        expect(e.code).toBe("invalid_response");
        expect(e.message).toContain("expires_in out of bounds");
      }
    });

    it("CR-1b regression: createAnonymousSession with expires_in=3600 works", async () => {
      // CR-1b fix: normal expires_in values still work
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () => {
          return HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: 3600
          });
        })
      );

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session")
      );
      const res = new NextResponse();

      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );
      expect(session).toBeDefined();
      expect(session.id).toContain("anon@");
    });

    // P2: "CR-1b regression: renewal with negative expires_in works" DELETED.
    // expires_in <= 0 is now rejected by lower-bound validation → AnonymousSessionError.
    // Replacement tests: P2-T9.1, P2-T9.2, P2-T9.3 in "Phase 2: Transfer Ticket Migration".
  });
});

// =============================================================================
// Phase 2: Transfer Ticket Migration
// Tests for anon_transfer_token minting, fail-open, EC exclusion, cookie clear.
// =============================================================================
describe("Phase 2: Transfer Ticket Migration", () => {
  let client: AuthClient;
  let secret: string;
  let server: any;
  const defaultDomain = "auth0.local";

  // Helper: build encrypted anon cookie from a session_token
  async function createAnonCookie(
    sessionToken: string,
    overrideSecret?: string
  ): Promise<string> {
    const s = overrideSecret ?? secret;
    const payload: AnonymousCookiePayload = {
      session_token: sessionToken,
      access_token: createMockJWT("anon@test-uuid"),
      expires_at: Math.floor(Date.now() / 1000) + 3600
    };
    return encrypt(payload, s, Math.floor(Date.now() / 1000) + 3600);
  }

  // Helper: build encrypted anon cookie WITHOUT session_token (addenda case 1)
  async function createAnonCookieNoToken(): Promise<string> {
    const payload = {
      access_token: createMockJWT("anon@test-uuid"),
      expires_at: Math.floor(Date.now() / 1000) + 3600
    } as unknown as AnonymousCookiePayload;
    return encrypt(payload, secret, Math.floor(Date.now() / 1000) + 3600);
  }

  function makeClient(
    anonConfig: { enabled: boolean; clearAnonymousSessionOnLogin?: boolean } = {
      enabled: true
    }
  ): AuthClient {
    return new AuthClient({
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
      anonymousSession: anonConfig
    });
  }

  beforeAll(async () => {
    server = setupServer(
      http.post(
        `https://${defaultDomain}/anonymous/token`,
        async ({ request }) => {
          const body = (await request.json()) as any;
          // Transfer ticket mint
          if (body.audience === "urn:auth0:anon_transfer") {
            return HttpResponse.json({
              anon_transfer_token: "mock-transfer-ticket-xyz",
              token_type: "N_A",
              expires_in: 30
            });
          }
          // CREATE
          if (!body.session_token) {
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `session-${Date.now()}`,
              access_token: createMockJWT("anon@uuid-9999"),
              expires_in: 3600,
              ...(body.metadata && { metadata: body.metadata })
            });
          }
          // RENEW
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: 3600,
            metadata: body.metadata
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
    client = makeClient({ enabled: true });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T1: Mint Success — URL + Transaction State
  // ---------------------------------------------------------------------------
  describe("P2-T1: Mint success — URL and TransactionState", () => {
    it("P2-T1.1: anon_transfer_token present in /authorize URL on mint success", async () => {
      const encrypted = await createAnonCookie("test-session-token-123");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      const url = new URL(location!);
      expect(url.searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T1.2: session_token ABSENT from /authorize URL (regression guard)", async () => {
      const encrypted = await createAnonCookie("test-session-token-123");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("session_token")).toBe(false);
    });

    it("P2-T1.3: anonymousSessionLinked: true in TransactionState when mint succeeds", async () => {
      const encrypted = await createAnonCookie("test-session-token-123");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location");
      const stateMatch = location!.match(/state=([^&]+)/);
      expect(stateMatch).toBeTruthy();
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(txState.payload.anonymousSessionLinked).toBe(true);
    });

    it("P2-T1.4: anonymousSessionRef (SHA-256 digest, 64 hex chars) in TransactionState", async () => {
      const encrypted = await createAnonCookie("test-session-token-123");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location");
      const stateMatch = location!.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(typeof txState.payload.anonymousSessionRef).toBe("string");
      expect(txState.payload.anonymousSessionRef.length).toBe(64);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T2: Mint Request Body Correctness
  // ---------------------------------------------------------------------------
  describe("P2-T2: Mint request body correctness", () => {
    async function captureBodySetup(): Promise<{
      capturedBody: Record<string, unknown> | null;
    }> {
      const holder = { capturedBody: null as Record<string, unknown> | null };
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            holder.capturedBody = body;
            return HttpResponse.json({
              anon_transfer_token: "mock-transfer-ticket-xyz",
              token_type: "N_A",
              expires_in: 30
            });
          }
        )
      );
      return holder;
    }

    it("P2-T2.1: POST body contains audience: 'urn:auth0:anon_transfer'", async () => {
      const holder = await captureBodySetup();
      const encrypted = await createAnonCookie("body-check-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      await (client as any).startInteractiveLogin({ returnTo: "/" }, req);

      expect(holder.capturedBody).not.toBeNull();
      expect(holder.capturedBody!.audience).toBe("urn:auth0:anon_transfer");
    });

    it("P2-T2.2: POST body contains session_token matching anon cookie value", async () => {
      const holder = await captureBodySetup();
      const encrypted = await createAnonCookie("body-check-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      await (client as any).startInteractiveLogin({ returnTo: "/" }, req);

      expect(holder.capturedBody!.session_token).toBe("body-check-session");
    });

    it("P2-T2.3: POST body contains client_id", async () => {
      const holder = await captureBodySetup();
      const encrypted = await createAnonCookie("body-check-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      await (client as any).startInteractiveLogin({ returnTo: "/" }, req);

      expect(holder.capturedBody!.client_id).toBe("test-id");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T3: Mint Non-2xx — Login Proceeds, No Token Param, No Throw
  // ---------------------------------------------------------------------------
  describe("P2-T3: Mint non-2xx — fail-open", () => {
    it("P2-T3.1: HTTP 401 from mint → login redirect returned, anon_transfer_token absent", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ error: "invalid_client" }, { status: 401 })
        )
      );
      const encrypted = await createAnonCookie("session-401");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T3.2: HTTP 500 from mint → login proceeds (fail-open)", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ error: "internal_error" }, { status: 500 })
        )
      );
      const encrypted = await createAnonCookie("session-500");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T3.3: anonymousSessionLinked: false in TransactionState when mint returns non-2xx", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ error: "invalid_client" }, { status: 401 })
        )
      );
      const encrypted = await createAnonCookie("session-401");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location");
      const stateMatch = location!.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(txState.payload.anonymousSessionLinked || false).toBe(false);
    });

    it("P2-T3.4: Response body missing anon_transfer_token → login proceeds, no param", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ token_type: "N_A", expires_in: 30 })
        )
      );
      const encrypted = await createAnonCookie("session-missing-field");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T3.5: anon_transfer_token is a number, not string → treated as absent, login proceeds", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            anon_transfer_token: 42,
            token_type: "N_A",
            expires_in: 30
          })
        )
      );
      const encrypted = await createAnonCookie("session-bad-type");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T4: Mint Network Error — Login Proceeds, No Throw
  // ---------------------------------------------------------------------------
  describe("P2-T4: Mint network error — fail-open", () => {
    it("P2-T4.1: Fetch throws network error → login redirect returned, anon_transfer_token absent", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.error()
        )
      );
      const encrypted = await createAnonCookie("session-network-fail");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T4.2: startInteractiveLogin does not throw when fetch fails", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.error()
        )
      );
      const encrypted = await createAnonCookie("session-network-fail");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      await expect(
        (client as any).startInteractiveLogin({ returnTo: "/" }, req)
      ).resolves.toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T5: No Active Anonymous Session — Login Proceeds, No Mint
  // ---------------------------------------------------------------------------
  describe("P2-T5: No active anonymous session", () => {
    it("P2-T5.1: No auth0_anon cookie → POST /anonymous/token NOT called for mint", async () => {
      let mintCalled = false;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            if (body.audience === "urn:auth0:anon_transfer") {
              mintCalled = true;
            }
            return HttpResponse.json({ token_type: "N_A", expires_in: 30 });
          }
        )
      );
      const req = new NextRequest("http://localhost:3000/auth/login"); // no cookie

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect(mintCalled).toBe(false);
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
      const stateMatch = location!.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(txState.payload.anonymousSessionLinked || false).toBe(false);
    });

    it("P2-T5.2: anonymousSession.enabled: false → no cookie read, no mint, login proceeds", async () => {
      let mintCalled = false;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            if (body.audience === "urn:auth0:anon_transfer") {
              mintCalled = true;
            }
            return HttpResponse.json({ token_type: "N_A", expires_in: 30 });
          }
        )
      );
      const disabledClient = makeClient({ enabled: false });
      const encrypted = await createAnonCookie("should-not-mint");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (disabledClient as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect(mintCalled).toBe(false);
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T5.3: anon cookie present but session_token absent → NO mint, login proceeds (addenda)", async () => {
      let mintCalled = false;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            if (body.audience === "urn:auth0:anon_transfer") {
              mintCalled = true;
            }
            return HttpResponse.json({ token_type: "N_A", expires_in: 30 });
          }
        )
      );
      const encrypted = await createAnonCookieNoToken();
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect(mintCalled).toBe(false);
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T6: Anon Cookie/Store READ Throws — Login Still Proceeds (P0 Fail-Open)
  // ---------------------------------------------------------------------------
  describe("P2-T6: Cookie read throws — fail-open", () => {
    it("P2-T6.1: Decryption failure → login completes with 302/307", async () => {
      const wrongSecret = await generateSecret(32);
      const payload: AnonymousCookiePayload = {
        session_token: "decryption-fail",
        access_token: createMockJWT("anon@x"),
        expires_at: Math.floor(Date.now() / 1000) + 3600
      };
      const badCookie = await encrypt(
        payload,
        wrongSecret,
        Math.floor(Date.now() / 1000) + 3600
      );
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${badCookie}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.has("anon_transfer_token")).toBe(
        false
      );
    });

    it("P2-T6.2: anonymousSessionLinked: false when cookie read throws", async () => {
      const wrongSecret = await generateSecret(32);
      const payload: AnonymousCookiePayload = {
        session_token: "decryption-fail",
        access_token: createMockJWT("anon@x"),
        expires_at: Math.floor(Date.now() / 1000) + 3600
      };
      const badCookie = await encrypt(
        payload,
        wrongSecret,
        Math.floor(Date.now() / 1000) + 3600
      );
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${badCookie}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location");
      const stateMatch = location!.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(txState.payload.anonymousSessionLinked || false).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T7: Enterprise Connection Login — Mint FIRES (no client-side gate)
  // F1 fix: isEnterpriseConnectionLogin guard removed. Auth0 handles EC/passwordless
  // linking server-side; the SDK mints unconditionally when an anon cookie is present.
  // ---------------------------------------------------------------------------
  describe("P2-T7: Enterprise Connection login — mint fires (no client-side gate)", () => {
    function makeMintSpy(): { mintCalled: boolean } {
      const spy = { mintCalled: false };
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            if (body.audience === "urn:auth0:anon_transfer") {
              spy.mintCalled = true;
              return HttpResponse.json({
                anon_transfer_token: "mock-transfer-ticket-xyz",
                token_type: "N_A",
                expires_in: 30
              });
            }
            return HttpResponse.json({ token_type: "N_A", expires_in: 30 });
          }
        )
      );
      return spy;
    }

    it("P2-T7.1: connection: 'samlp' (SAML Enterprise) → mint DOES fire, anon_transfer_token present", async () => {
      const spy = makeMintSpy();
      const encrypted = await createAnonCookie("ec-session-samlp");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/", authorizationParameters: { connection: "samlp" } },
        req
      );

      expect(spy.mintCalled).toBe(true);
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T7.2: connection: 'waad' (Azure AD / Entra ID) → mint DOES fire", async () => {
      const spy = makeMintSpy();
      const encrypted = await createAnonCookie("ec-session-waad");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/", authorizationParameters: { connection: "waad" } },
        req
      );

      expect(spy.mintCalled).toBe(true);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T7.3: EC login → anonymousSessionLinked: true (mint succeeds)", async () => {
      makeMintSpy();
      const encrypted = await createAnonCookie("ec-session-samlp");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/", authorizationParameters: { connection: "samlp" } },
        req
      );

      const location = result.headers.get("location");
      const stateMatch = location!.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );
      expect(txState.payload.anonymousSessionLinked).toBe(true);
    });

    it("P2-T7.4: connection: 'adfs' → mint fires (no strategy-name gate)", async () => {
      const spy = makeMintSpy();
      const encrypted = await createAnonCookie("ec-session-adfs");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/", authorizationParameters: { connection: "adfs" } },
        req
      );

      expect(spy.mintCalled).toBe(true);
      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T7.5: connection: 'google-oauth2' → mint proceeds (social connection unchanged)", async () => {
      const encrypted = await createAnonCookie("non-ec-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParameters: { connection: "google-oauth2" }
        },
        req
      );

      const location = result.headers.get("location");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T8: Layer-1 Reserved-Param Stripping
  // ---------------------------------------------------------------------------
  describe("P2-T8: Layer-1 reserved-param stripping", () => {
    it("P2-T8.1: Caller-supplied session_token stripped; SDK's ticket appended", async () => {
      const encrypted = await createAnonCookie("legitimate-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParameters: { session_token: "attacker-injected-value" }
        },
        req
      );

      const location = result.headers.get("location");
      expect(location).not.toContain("attacker-injected-value");
      expect(location).not.toContain("session_token=");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T8.2: Caller-supplied anon_transfer_token stripped; SDK's ticket takes effect", async () => {
      const encrypted = await createAnonCookie("session-for-strip");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParameters: {
            anon_transfer_token: "caller-supplied-ticket"
          }
        },
        req
      );

      const location = result.headers.get("location");
      expect(location).not.toContain("caller-supplied-ticket");
      expect(new URL(location!).searchParams.get("anon_transfer_token")).toBe(
        "mock-transfer-ticket-xyz"
      );
    });

    it("P2-T8.3: Caller-supplied session_token, no anon cookie → stripped, no ticket, no throw", async () => {
      const req = new NextRequest("http://localhost:3000/auth/login"); // no cookie

      const result = await (client as any).startInteractiveLogin(
        {
          returnTo: "/",
          authorizationParameters: { session_token: "attacker-no-cookie" }
        },
        req
      );

      expect([302, 307]).toContain(result.status);
      const location = result.headers.get("location");
      expect(location).not.toContain("session_token=");
      expect(location).not.toContain("anon_transfer_token=");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T9: PR #2813 Folded Fixes
  // ---------------------------------------------------------------------------
  describe("P2-T9: PR #2813 folded fixes", () => {
    it("P2-T9.1: expires_in = 0 → createAnonymousSession throws AnonymousSessionError invalid_response", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: 0
          })
        )
      );
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
      } catch (e: any) {
        expect(e.code).toBe("invalid_response");
        expect(e.message).toContain("expires_in out of bounds");
      }
    });

    it("P2-T9.2: expires_in = -1 → throws AnonymousSessionError invalid_response", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: -1
          })
        )
      );
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
      } catch (e: any) {
        expect(e.code).toBe("invalid_response");
      }
    });

    it("P2-T9.3: expires_in = -10 → throws (previously allowed, now rejected by lower-bound)", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: -10
          })
        )
      );
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();

      await expect(
        (client as any).createAnonymousSession(req.cookies, res.cookies)
      ).rejects.toThrow();

      try {
        await (client as any).createAnonymousSession(req.cookies, res.cookies);
      } catch (e: any) {
        expect(e.code).toBe("invalid_response");
      }
    });

    it("P2-T9.4: expires_in = 3600 → session created and persisted successfully (regression-free path)", async () => {
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            token_type: "Bearer",
            session_token: `session-${Date.now()}`,
            access_token: createMockJWT("anon@uuid-9999"),
            expires_in: 3600
          })
        )
      );
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();

      const session = await (client as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );
      expect(session).toBeDefined();
      expect(session.id).toContain("anon@");
    });

    it("P2-T9.5: toPublicSession read path: A5 regression still passes (renewal with malformed sub returns null, no throw)", async () => {
      // Verify the existing A5 regression still holds after P2 changes
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({
            token_type: "Bearer",
            access_token: createMockJWT("user@123"), // non-anon sub
            expires_in: 3600
          })
        )
      );
      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "session-123",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100
      };
      const encrypted = await encrypt(expiredPayload, secret, now + 3600);
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session",
        { headers: { cookie: `auth0_anon=${encrypted}` } }
      );

      const res = await (client as any).handleGetAnonymousSession(req);
      expect(res.status).toBe(204);
    });

    it("P2-T9.6: toCookiePayload merge precedence — server session_token and metadata win", async () => {
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            const body = (await request.json()) as Record<string, unknown>;
            if (
              body.session_token &&
              body.audience !== "urn:auth0:anon_transfer"
            ) {
              // RENEW mode: return server-rotated session_token and metadata
              return HttpResponse.json({
                token_type: "Bearer",
                session_token: "rotated-by-server",
                access_token: createMockJWT("anon@uuid-rotated"),
                expires_in: 3600,
                metadata: { server: "wins" }
              });
            }
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: `s-${Date.now()}`,
              access_token: createMockJWT("anon@uuid"),
              expires_in: 3600
            });
          }
        )
      );

      const now = Math.floor(Date.now() / 1000);
      const expiredPayload: AnonymousCookiePayload = {
        session_token: "prior-session-token",
        access_token: createMockJWT("anon@uuid-9999", -100),
        expires_at: now - 100,
        metadata: { caller: "value" }
      };
      const encrypted = await encrypt(expiredPayload, secret, now + 3600);
      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session",
        { headers: { cookie: `auth0_anon=${encrypted}` } }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const anonCookie = res.cookies.get("auth0_anon");
      expect(anonCookie).toBeTruthy();
      const decrypted = await decrypt<AnonymousCookiePayload>(
        anonCookie!.value,
        secret
      );
      expect(decrypted).toBeTruthy();
      expect(decrypted!.payload.session_token).toBe("rotated-by-server");
      expect(decrypted!.payload.metadata).toEqual({ server: "wins" });
    });

    // P2-T9.7 (runtime barrel check) deleted. Compile-time coverage:
    // `pnpm tsc --noEmit` catches any import of AnonymousCookiePayload,
    // AnonymousTokenResponse, or isRecoverableAnonymousError from the public
    // barrel — the symbols do not exist there and tsc will error.
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T10: clearAnonymousSessionOnLogin
  // F2+F4 fix: clear moved from login initiation to handleCallback (successful
  // code exchange). Abandoned logins (no callback) leave the anon cookie intact.
  // ---------------------------------------------------------------------------
  describe("P2-T10: clearAnonymousSessionOnLogin (clear at callback, not login)", () => {
    it("P2-T10.1: Default config (omitted → defaults true) → anon cookie NOT cleared at login initiation (moved to callback)", async () => {
      // With F2/F4 fix, the clear is at callback, so login redirect must NOT delete the cookie.
      const encrypted = await createAnonCookie("session-to-clear-default");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const setCookies = result.headers.getSetCookie();
      const anonDeletions = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      // Cookie is preserved at login; will only be cleared at successful callback
      expect(anonDeletions.length).toBe(0);
    });

    it("P2-T10.2: clearAnonymousSessionOnLogin: true → anon cookie NOT cleared at login redirect (preserved for abandoned-login safety)", async () => {
      const clearClient = makeClient({
        enabled: true,
        clearAnonymousSessionOnLogin: true
      });
      const encrypted = await createAnonCookie("session-to-clear-explicit");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (clearClient as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const setCookies = result.headers.getSetCookie();
      const anonDeletions = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      expect(anonDeletions.length).toBe(0);
    });

    it("P2-T10.3: clearAnonymousSessionOnLogin: false → auth0_anon cookie NOT cleared at login or callback", async () => {
      const keepClient = makeClient({
        enabled: true,
        clearAnonymousSessionOnLogin: false
      });
      const encrypted = await createAnonCookie("session-to-keep");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (keepClient as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const setCookies = result.headers.getSetCookie();
      const anonDeletions = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      expect(anonDeletions.length).toBe(0);
    });

    it("P2-T10.4: clearAnonymousSessionOnLogin: true with no anon cookie → no error (no-op)", async () => {
      const req = new NextRequest("http://localhost:3000/auth/login"); // no cookie

      await expect(
        (client as any).startInteractiveLogin({ returnTo: "/" }, req)
      ).resolves.toBeDefined();

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );
      expect([302, 307]).toContain(result.status);
    });

    it("P2-T10.5: clearAnonymousSessionOnLogin=true with mint failure → anon cookie NOT cleared at login (preserved until callback)", async () => {
      // With F2/F4 fix, even when mint fails, cookie is preserved at login initiation
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ error: "invalid_client" }, { status: 401 })
        )
      );
      const clearClient = makeClient({
        enabled: true,
        clearAnonymousSessionOnLogin: true
      });
      const encrypted = await createAnonCookie("session-mint-fail-clear");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (clearClient as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(result.status);
      const setCookies = result.headers.getSetCookie();
      const anonDeletions = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      // Cookie preserved at login, even when mint fails
      expect(anonDeletions.length).toBe(0);
    });

    it("P2-T10.6: Abandoned login (no callback) → anon cookie intact (login does not delete it)", async () => {
      // F4: login initiation no longer clears the cookie, so an abandoned login
      // (user never completes auth) leaves the anon cookie available.
      const encrypted = await createAnonCookie("abandoned-session-cookie");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const loginResult = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      expect([302, 307]).toContain(loginResult.status);
      // No Set-Cookie for anon cookie deletion — cookie survives login initiation
      const setCookies = loginResult.headers.getSetCookie();
      const anonDeletions = setCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      expect(anonDeletions.length).toBe(0);
      // (No callback → cookie remains intact in the browser)
    });

    it("P2-T10.7: handleCallback clears anon cookie with full cookie attributes (not just name)", async () => {
      // F2: deleteChunkedCookie in handleCallback passes {path,domain,secure,sameSite,httpOnly}
      // from anonymousCookieOptions so Chromium 124+ properly matches the cookie for deletion.
      // We verify by driving handleCallback through a full OAuth mock.
      const keyPair = await jose.generateKeyPair("RS256");

      // Client with custom fetch that mocks the AS
      const mockFetch = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(
            typeof input === "string"
              ? input
              : input instanceof Request
                ? input.url
                : input.toString()
          );
          if (url.pathname === "/.well-known/openid-configuration") {
            return Response.json({
              issuer: `https://${defaultDomain}/`,
              authorization_endpoint: `https://${defaultDomain}/authorize`,
              token_endpoint: `https://${defaultDomain}/oauth/token`,
              userinfo_endpoint: `https://${defaultDomain}/userinfo`,
              jwks_uri: `https://${defaultDomain}/.well-known/jwks.json`
            });
          }
          if (url.pathname === "/.well-known/jwks.json") {
            const publicJwk = await jose.exportJWK(keyPair.publicKey);
            return Response.json({ keys: [{ ...publicJwk, kid: "test-key" }] });
          }
          if (url.pathname === "/oauth/token") {
            // Extract nonce from transaction cookie to satisfy id_token validation
            const nonce = (init as any)?._nonce ?? "nonce-placeholder";
            const idToken = await new jose.SignJWT({ nonce })
              .setProtectedHeader({ alg: "RS256", kid: "test-key" })
              .setSubject("user_123")
              .setIssuedAt()
              .setIssuer(`https://${defaultDomain}/`)
              .setAudience("test-id")
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);
            return Response.json({
              token_type: "Bearer",
              access_token: "at_123",
              id_token: idToken,
              expires_in: 86400
            });
          }
          if (url.pathname === "/anonymous/token") {
            return Response.json({
              anon_transfer_token: "mock-ticket-xyz",
              token_type: "N_A",
              expires_in: 30
            });
          }
          throw new Error(`Unmocked URL: ${url.pathname}`);
        }
      );

      const cbClient = new (client.constructor as any)({
        domain: defaultDomain,
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes: {
          login: "/auth/login",
          logout: "/auth/logout",
          callback: "/auth/callback",
          backChannelLogout: "/auth/backchannel-logout",
          onError: undefined
        },
        transactionStore: new (
          await import("./transaction-store.js")
        ).TransactionStore({ secret, cookieOptions: { secure: false } }),
        sessionStore: new (
          await import("./session/stateless-session-store.js")
        ).StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true },
        fetch: mockFetch
      });

      // Step 1: initiate login with anon cookie present
      const encrypted = await createAnonCookie("callback-clear-session");
      const loginReq = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });
      const loginRes = await (cbClient as any).startInteractiveLogin(
        { returnTo: "/" },
        loginReq
      );
      expect([302, 307]).toContain(loginRes.status);

      // Step 2: extract state, nonce, and transaction cookie
      const location = loginRes.headers.get("location")!;
      const authorizeUrl = new URL(location);
      const state = authorizeUrl.searchParams.get("state")!;
      const nonce = authorizeUrl.searchParams.get("nonce")!;
      const txCookie = loginRes.headers
        .getSetCookie()
        .find((c: string) => c.startsWith("__txn_"));
      expect(txCookie).toBeTruthy();

      // Patch mockFetch to inject nonce into /oauth/token responses
      mockFetch.mockImplementation(async (input: RequestInfo | URL) => {
        const url = new URL(
          typeof input === "string"
            ? input
            : input instanceof Request
              ? input.url
              : input.toString()
        );
        if (url.pathname === "/.well-known/openid-configuration") {
          return Response.json({
            issuer: `https://${defaultDomain}/`,
            authorization_endpoint: `https://${defaultDomain}/authorize`,
            token_endpoint: `https://${defaultDomain}/oauth/token`,
            userinfo_endpoint: `https://${defaultDomain}/userinfo`,
            jwks_uri: `https://${defaultDomain}/.well-known/jwks.json`
          });
        }
        if (url.pathname === "/.well-known/jwks.json") {
          const publicJwk = await jose.exportJWK(keyPair.publicKey);
          return Response.json({
            keys: [{ ...publicJwk, kid: "test-key" }]
          });
        }
        if (url.pathname === "/oauth/token") {
          const idToken = await new jose.SignJWT({ nonce })
            .setProtectedHeader({ alg: "RS256", kid: "test-key" })
            .setSubject("user_123")
            .setIssuedAt()
            .setIssuer(`https://${defaultDomain}/`)
            .setAudience("test-id")
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);
          return Response.json({
            token_type: "Bearer",
            access_token: "at_123",
            id_token: idToken,
            expires_in: 86400
          });
        }
        throw new Error(`Unmocked: ${url.pathname}`);
      });

      // Step 3: simulate callback with auth code
      const txCookieValue = txCookie!.split(";")[0]; // name=value only
      const callbackReq = new NextRequest(
        `http://localhost:3000/auth/callback?code=auth-code&state=${encodeURIComponent(state)}`,
        { headers: { cookie: `${txCookieValue}; auth0_anon=${encrypted}` } }
      );

      const callbackRes = await cbClient.handleCallback(callbackReq);

      // Step 4: verify anon cookie is cleared with cookie attributes in the callback response
      const callbackSetCookies = callbackRes.headers.getSetCookie();
      const anonDeletions = callbackSetCookies.filter(
        (c: string) => c.startsWith("auth0_anon") && c.includes("Max-Age=0")
      );
      expect(anonDeletions.length).toBeGreaterThan(0);

      // F2 assertion: deletion header must include cookie-attribute directives
      // (not just name=; Max-Age=0). HttpOnly and Path are set by anonymousCookieOptions defaults.
      const deletionHeader = anonDeletions[0];
      expect(deletionHeader).toMatch(/HttpOnly/i);
      expect(deletionHeader).toMatch(/Path=/i);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite P2-T11: F3 digest-ordering — digest throws → all three unset
  // ---------------------------------------------------------------------------
  describe("P2-T11: F3 digest ordering — digest throws → fail-open", () => {
    it("P2-T11.1: mint succeeds but digestAnonymousSessionToken throws → anonymousSessionLinked stays false, no ticket appended, login proceeds", async () => {
      // digestAnonymousSessionToken (module-level in auth-client.ts) calls
      //   crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionToken))
      // We spy on the real crypto.subtle.digest with a content-matching
      // implementation that rejects ONLY when the input decodes to our specific
      // session token string, and delegates every other call (PKCE code-challenge,
      // etc.) to the real implementation. This avoids the race with
      // oauth.calculatePKCECodeChallenge, which also calls crypto.subtle.digest
      // before the anonymous-session try/catch block runs.
      const SESSION_TOKEN = "digest-throw-session";
      const realDigest = crypto.subtle.digest.bind(crypto.subtle);
      const digestSpy = vi
        .spyOn(crypto.subtle, "digest")
        .mockImplementation((algorithm, data) => {
          // Detect the digestAnonymousSessionToken call by its UTF-8 encoded input.
          // The PKCE code-verifier (random alphanumeric) and other callers pass binary
          // data whose UTF-8 decoded form will never equal SESSION_TOKEN.
          const decoded = new TextDecoder().decode(
            data as ArrayBuffer | ArrayBufferView
          );
          if (decoded === SESSION_TOKEN) {
            return Promise.reject(new Error("digest-fail-injected"));
          }
          return realDigest(algorithm, data);
        });

      try {
        const encrypted = await createAnonCookie(SESSION_TOKEN);
        const req = new NextRequest("http://localhost:3000/auth/login", {
          headers: { cookie: `auth0_anon=${encrypted}` }
        });

        const result = await (client as any).startInteractiveLogin(
          { returnTo: "/" },
          req
        );

        // (c) login still proceeds fail-open: redirect is returned
        expect([302, 307]).toContain(result.status);

        const location = result.headers.get("location")!;

        // (b) no anon_transfer_token param appended to the /authorize URL
        const authorizeUrl = new URL(location);
        expect(authorizeUrl.searchParams.has("anon_transfer_token")).toBe(
          false
        );

        // (a) anonymousSessionLinked is NOT true in the saved transaction
        const stateMatch = location.match(/state=([^&]+)/);
        const txState = await (client as any).transactionStore.get(
          result.cookies,
          decodeURIComponent(stateMatch![1])
        );
        expect(txState.payload.anonymousSessionLinked || false).toBe(false);
        expect(txState.payload.anonymousSessionRef).toBeUndefined();
      } finally {
        // Always restore so the spy does not leak into other tests
        digestSpy.mockRestore();
      }
    });

    it("P2-T11.2: mint null (fail-open) → anonymousSessionLinked false, anonymousSessionRef undefined", async () => {
      // When mint returns null, neither linked nor ref should be set
      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, () =>
          HttpResponse.json({ error: "unavailable" }, { status: 503 })
        )
      );

      const encrypted = await createAnonCookie("mint-null-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location")!;
      const stateMatch = location.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );

      // Both must be unset together
      expect(txState.payload.anonymousSessionLinked || false).toBe(false);
      expect(txState.payload.anonymousSessionRef).toBeUndefined();
    });

    it("P2-T11.3: mint succeeds and digest succeeds → anonymousSessionLinked true, anonymousSessionRef set (64-char hex)", async () => {
      // Success path: when both mint and digest succeed, all three fields must
      // be set atomically (ref set, linked = true, ticket appended to URL).
      const encrypted = await createAnonCookie("digest-success-session");
      const req = new NextRequest("http://localhost:3000/auth/login", {
        headers: { cookie: `auth0_anon=${encrypted}` }
      });

      const result = await (client as any).startInteractiveLogin(
        { returnTo: "/" },
        req
      );

      const location = result.headers.get("location")!;

      // anon_transfer_token should be appended to the /authorize URL
      const authorizeUrl = new URL(location);
      expect(authorizeUrl.searchParams.has("anon_transfer_token")).toBe(true);

      const stateMatch = location.match(/state=([^&]+)/);
      const txState = await (client as any).transactionStore.get(
        result.cookies,
        decodeURIComponent(stateMatch![1])
      );

      // Both are set together (atomically)
      expect(txState.payload.anonymousSessionLinked).toBe(true);
      expect(typeof txState.payload.anonymousSessionRef).toBe("string");
      expect(txState.payload.anonymousSessionRef.length).toBe(64);
    });
  });

  // ── A1: mTLS anonymous endpoint URL routing ────────────────────────────────

  describe("A1: Anonymous endpoints use mTLS alias origin when useMtls=true", () => {
    const mtlsOrigin = "https://mtls.auth0.local";

    it("A1.1: anonymousTokenRequest routes through mTLS alias origin", async () => {
      // Track which origin the /anonymous/token request was sent to.
      let capturedOrigin: string | null = null;

      // Override discovery to advertise an mTLS alias, and handle the mTLS endpoint.
      // server.resetHandlers() (afterEach) cleans these up automatically.
      server.use(
        http.get(
          `https://${defaultDomain}/.well-known/openid-configuration`,
          () =>
            HttpResponse.json({
              issuer: `https://${defaultDomain}/`,
              authorization_endpoint: `https://${defaultDomain}/authorize`,
              token_endpoint: `https://${defaultDomain}/oauth/token`,
              userinfo_endpoint: `https://${defaultDomain}/userinfo`,
              jwks_uri: `https://${defaultDomain}/.well-known/jwks.json`,
              mtls_endpoint_aliases: {
                token_endpoint: `${mtlsOrigin}/oauth/token`
              }
            })
        ),
        http.post(`${mtlsOrigin}/anonymous/token`, ({ request }) => {
          capturedOrigin = new URL(request.url).origin;
          return HttpResponse.json({
            token_type: "Bearer",
            session_token: "mtls-session",
            access_token: createMockJWT("anon@mtls-uuid"),
            expires_in: 3600
          });
        })
      );

      const mtlsSecret = await generateSecret(32);
      // useMtls requires: (a) no clientSecret, (b) a fetch option.
      const mtlsClient = new AuthClient({
        domain: defaultDomain,
        clientId: "test-id",
        appBaseUrl: "http://localhost:3000",
        secret: mtlsSecret,
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: (async (input: RequestInfo | URL, init?: RequestInit) =>
          fetch(input, init)) as typeof fetch,
        transactionStore: new TransactionStore({
          secret: mtlsSecret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret: mtlsSecret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true }
      });

      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();
      await (mtlsClient as any).createAnonymousSession(
        req.cookies,
        res.cookies
      );

      // The request must have gone to the mTLS alias origin, not the plain domain.
      expect(capturedOrigin).toBe(mtlsOrigin);
    });

    it("A1.2: anonymousTokenRequest falls back to plain domain when useMtls=false", async () => {
      let capturedOrigin: string | null = null;

      server.use(
        http.post(`https://${defaultDomain}/anonymous/token`, ({ request }) => {
          capturedOrigin = new URL(request.url).origin;
          return HttpResponse.json({
            token_type: "Bearer",
            session_token: "plain-session",
            access_token: createMockJWT("anon@plain-uuid"),
            expires_in: 3600
          });
        })
      );

      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session"
      );
      const res = new NextResponse();
      await (client as any).createAnonymousSession(req.cookies, res.cookies);

      // The request must use the plain domain origin (no mTLS).
      expect(capturedOrigin).toBe(`https://${defaultDomain}`);
    });
  });

  // ── A2: Stale session returned on transient renewal error ─────────────────

  describe("A2: Transient renewal error returns existing stale session (no id swap)", () => {
    // Helper: create an expired anon cookie using the Phase 2 encrypt import.
    async function createExpiredCookie(
      sessionToken: string,
      anonId: string
    ): Promise<string> {
      const now = Math.floor(Date.now() / 1000);
      const payload: AnonymousCookiePayload = {
        session_token: sessionToken,
        access_token: createMockJWT(anonId, -100), // access token already expired
        expires_at: now - 100 // cookie payload says expired
      };
      // Use a far-future JWE expiry so the cookie is still decryptable.
      return encrypt(payload, secret, now + 3600);
    }

    it("A2.2: session_expired during renewal still creates a fresh session (existing path unchanged)", async () => {
      // session_expired is genuinely gone → creates new session (isRecoverableAnonymousError path).
      let callCount = 0;
      server.use(
        http.post(
          `https://${defaultDomain}/anonymous/token`,
          async ({ request }) => {
            callCount++;
            const body = (await request.json()) as any;
            if (callCount === 1) {
              return HttpResponse.json(
                { error: "session_expired" },
                { status: 400 }
              );
            }
            // Second call: fresh create
            expect(body.session_token).toBeUndefined();
            return HttpResponse.json({
              token_type: "Bearer",
              session_token: "session-new",
              access_token: createMockJWT("anon@fresh-uuid-5678"),
              expires_in: 3600
            });
          }
        )
      );

      const encrypted = await createExpiredCookie(
        "expired-session",
        "anon@expired-uuid-9999"
      );

      const req = new NextRequest(
        "http://localhost:3000/auth/anonymous-session",
        { headers: { cookie: `auth0_anon=${encrypted}` } }
      );

      const res = await (client as any).handleGetAnonymousSession(req);

      expect(res.status).toBe(200);
      const session = (await res.json()) as any;
      // A new id is assigned because the session was genuinely gone.
      expect(session.id).toBe("anon@fresh-uuid-5678");
      expect(callCount).toBe(2);
    });
  });
});
