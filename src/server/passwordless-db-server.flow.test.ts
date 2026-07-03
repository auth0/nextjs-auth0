import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { generateDpopKeyPair } from "../utils/dpopRetry.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  email: "user@example.com",
  phoneNumber: "+14155550100",
  otp: "123456",
  authSession: "opaque-auth-session-token",
  connection: "my-db-connection",
  accessToken: "test-access-token",
  sub: "auth0|test-user-id",
  sid: "test-sid-abc"
};

const CHALLENGE_URL = `https://${DEFAULT.domain}/otp/challenge`;
const TOKEN_URL = `https://${DEFAULT.domain}/oauth/token`;

// RSA key pair for signing id_tokens in route handler tests.
// Shared across the file; generated once before all tests run.
let keyPair: jose.GenerateKeyPairResult;

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(createAuthorizationServerMetadata(DEFAULT.domain));
  }),
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

/** Build a signed id_token using the module-level RSA key pair. */
async function generateIdToken(
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

describe("AuthClient passwordless DB route handlers", () => {
  let secret: string;
  let authClient: AuthClient;

  beforeEach(async () => {
    secret = await generateSecret(32);
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    authClient = new AuthClient({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      secret,
      transactionStore,
      sessionStore,
      routes: getDefaultRoutes()
    });
  });

  // ---------------------------------------------------------------------------
  // POST /auth/passwordless/otp/challenge
  // ---------------------------------------------------------------------------

  describe("POST /auth/passwordless/otp/challenge", () => {
    it("returns 200 with authSession for valid email challenge", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json({ auth_session: DEFAULT.authSession })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            email: DEFAULT.email,
            connection: DEFAULT.connection
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.authSession).toBe(DEFAULT.authSession);
    });

    it("returns 200 with authSession for valid phone challenge", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json({ auth_session: DEFAULT.authSession })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            phoneNumber: DEFAULT.phoneNumber,
            connection: DEFAULT.connection
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.authSession).toBe(DEFAULT.authSession);
    });

    it("does not forward delivery_method to Auth0 when not provided in request", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            phoneNumber: DEFAULT.phoneNumber,
            connection: DEFAULT.connection
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      await authClient.handler(req);
      expect(capturedBody.delivery_method).toBeUndefined();
    });

    it("forwards delivery_method to Auth0 when explicitly provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            phoneNumber: DEFAULT.phoneNumber,
            connection: DEFAULT.connection,
            deliveryMethod: "voice"
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      await authClient.handler(req);
      expect(capturedBody.delivery_method).toBe("voice");
    });

    it("returns 400 with missing_identifier when neither email nor phoneNumber is provided", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ connection: DEFAULT.connection }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("missing_identifier");
    });

    it("returns 400 when connection field is missing", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ email: DEFAULT.email }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBeTruthy();
    });

    it("returns 400 with Auth0 error details on invalid_connection", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_connection",
              error_description: "Connection is not a database connection."
            },
            { status: 400 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            email: DEFAULT.email,
            connection: "not-a-db-connection"
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("invalid_connection");
      expect(body.error_description).toBe(
        "Connection is not a database connection."
      );
    });

    it("returns 500 on network failure to Auth0", async () => {
      server.use(http.post(CHALLENGE_URL, () => HttpResponse.error()));

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            email: DEFAULT.email,
            connection: DEFAULT.connection
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(500);
    });
  });

  // ---------------------------------------------------------------------------
  // POST /auth/passwordless/otp/token
  // ---------------------------------------------------------------------------

  describe("POST /auth/passwordless/otp/token", () => {
    it("returns 200 + Set-Cookie and creates session on valid OTP", async () => {
      const idToken = await generateIdToken();

      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "Bearer",
            expires_in: 86400,
            id_token: idToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: DEFAULT.otp
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      expect((await res.json()).success).toBe(true);
      expect(res.headers.get("set-cookie")).toBeTruthy();
    });

    it("returns 400 for invalid_request (wrong or expired OTP) — not 403 or 500", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 400 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: "wrong-otp"
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe("Invalid or expired OTP code.");
    });

    it("returns 400 when authSession field is missing", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ otp: DEFAULT.otp }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBeTruthy();
    });

    it("returns 400 when otp field is missing", async () => {
      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ authSession: DEFAULT.authSession }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBeTruthy();
    });

    it("returns 500 for discovery_error", async () => {
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => HttpResponse.error()
        )
      );

      const freshSecret = await generateSecret(32);
      const freshClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: freshSecret,
        transactionStore: new TransactionStore({ secret: freshSecret }),
        sessionStore: new StatelessSessionStore({ secret: freshSecret }),
        routes: getDefaultRoutes()
      });

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: DEFAULT.otp
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await freshClient.handler(req);
      expect(res.status).toBe(500);
    });

    it("returns 403 with encrypted mfa_token when Auth0 returns mfa_required", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Multi-factor authentication required.",
              mfa_token: "raw-mfa-token-db"
            },
            { status: 403 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: DEFAULT.otp
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe("mfa_required");
      // mfa_token is encrypted — non-empty and not the raw value
      expect(typeof body.mfa_token).toBe("string");
      expect(body.mfa_token.length).toBeGreaterThan(0);
      expect(body.mfa_token).not.toBe("raw-mfa-token-db");
    });

    it("does not set a session cookie on mfa_required — no session established yet", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "MFA required.",
              mfa_token: "raw-mfa-token-db"
            },
            { status: 403 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: DEFAULT.otp
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(403);
      expect(res.headers.get("set-cookie")).toBeNull();
    });

    it("returns 400 with invalid_issuer when id_token iss does not match domain", async () => {
      const idToken = await new jose.SignJWT({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid
      })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer("https://wrong.tenant.auth0.com")
        .setAudience(DEFAULT.clientId)
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(keyPair.privateKey);

      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "Bearer",
            expires_in: 86400,
            id_token: idToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passwordless/otp/token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            otp: DEFAULT.otp
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("invalid_issuer");
    });
  });

  // ---------------------------------------------------------------------------
  // DPoP: nonce retry on passwordlessDbGetToken
  // ---------------------------------------------------------------------------

  describe("DPoP-enabled passwordlessDbGetToken", () => {
    it("retries with server-supplied nonce on use_dpop_nonce and sends DPoP proof on both attempts", async () => {
      const dpopKeyPair = await generateDpopKeyPair();
      const dpopSecret = await generateSecret(32);

      const dpopClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: dpopSecret,
        transactionStore: new TransactionStore({ secret: dpopSecret }),
        sessionStore: new StatelessSessionStore({ secret: dpopSecret }),
        routes: getDefaultRoutes(),
        useDPoP: true,
        dpopKeyPair
      });

      const idToken = await generateIdToken();
      const tokenRequests: Array<{ hasDPoP: boolean; dpopNonce?: string }> = [];
      let callCount = 0;

      server.use(
        http.post(TOKEN_URL, async ({ request }) => {
          callCount++;
          const dpopHeader = request.headers.get("dpop");
          let dpopNonce: string | undefined;

          if (dpopHeader) {
            try {
              const [, payloadB64] = dpopHeader.split(".");
              const payload = JSON.parse(
                Buffer.from(payloadB64, "base64url").toString()
              );
              dpopNonce = payload.nonce as string | undefined;
            } catch {
              // ignore parse errors
            }
          }

          tokenRequests.push({ hasDPoP: !!dpopHeader, dpopNonce });

          if (callCount === 1) {
            return HttpResponse.json(
              {
                error: "use_dpop_nonce",
                error_description:
                  "Authorization server requires nonce in DPoP proof"
              },
              {
                status: 400,
                headers: { "dpop-nonce": "server-nonce-db-abc" }
              }
            );
          }

          return HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "Bearer",
            expires_in: 86400,
            id_token: idToken
          });
        })
      );

      const result = await dpopClient.passwordlessDbGetToken({
        authSession: DEFAULT.authSession,
        otp: DEFAULT.otp
      });

      expect(callCount).toBe(2);
      expect(tokenRequests[0].hasDPoP).toBe(true);
      expect(tokenRequests[1].hasDPoP).toBe(true);
      expect(tokenRequests[1].dpopNonce).toBe("server-nonce-db-abc");
      expect(result.access_token).toBe(DEFAULT.accessToken);
    });
  });
});
