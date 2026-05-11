import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopRetry.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { ServerPasswordlessClient } from "./passwordless/server-passwordless-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  email: "user@example.com",
  phoneNumber: "+14155550100",
  verificationCode: "123456",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token",
  sub: "auth0|test-user-id",
  sid: "test-sid-abc"
};

// RSA key pair for signing id_tokens in route handler tests.
// Shared across the file; generated once before all tests run.
let keyPair: jose.GenerateKeyPairResult;

const authorizationServerMetadata = createAuthorizationServerMetadata(
  DEFAULT.domain
);

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  }),

  // JWKS endpoint — serves the public key used to sign id_tokens in route handler tests.
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

async function _createSessionCookie(
  session: SessionData,
  secret: string
): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000 + 3600);
  return encrypt(session, secret, expiration);
}

describe("AuthClient passwordless methods", () => {
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
  // passwordlessStart
  // ---------------------------------------------------------------------------

  describe("passwordlessStart", () => {
    it("sends correct body for email connection", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passwordless/start`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return HttpResponse.json({}, { status: 200 });
          }
        )
      );

      await authClient.passwordlessStart({
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });

      expect(capturedBody.client_id).toBe(DEFAULT.clientId);
      expect(capturedBody.client_secret).toBe(DEFAULT.clientSecret);
      expect(capturedBody.connection).toBe("email");
      expect(capturedBody.email).toBe(DEFAULT.email);
      expect(capturedBody.send).toBe("code");
      expect(capturedBody.phone_number).toBeUndefined();
    });

    it("sends correct body for sms connection", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passwordless/start`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return HttpResponse.json({}, { status: 200 });
          }
        )
      );

      await authClient.passwordlessStart({
        connection: "sms",
        phoneNumber: DEFAULT.phoneNumber
      });

      expect(capturedBody.connection).toBe("sms");
      expect(capturedBody.phone_number).toBe(DEFAULT.phoneNumber);
      expect(capturedBody.email).toBeUndefined();
      expect(capturedBody.send).toBeUndefined();
    });

    it("throws PasswordlessStartError on Auth0 API error", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () => {
          return HttpResponse.json(
            {
              error: "bad.connection",
              error_description: "Connection not found."
            },
            { status: 400 }
          );
        })
      );

      await expect(
        authClient.passwordlessStart({
          connection: "email",
          email: DEFAULT.email,
          send: "code"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessStartError",
        error: "bad.connection",
        error_description: "Connection not found."
      });
    });

    it("throws PasswordlessStartError with unexpected_error on network failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passwordless/start`, () => {
          return HttpResponse.error();
        })
      );

      await expect(
        authClient.passwordlessStart({
          connection: "email",
          email: DEFAULT.email,
          send: "link"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessStartError",
        error: "unexpected_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // passwordlessVerify
  // ---------------------------------------------------------------------------

  describe("passwordlessVerify", () => {
    it("sends correct params for email connection and returns token response", async () => {
      let capturedParams: URLSearchParams = new URLSearchParams();

      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedParams = new URLSearchParams(await request.text());
            return HttpResponse.json({
              access_token: DEFAULT.accessToken,
              refresh_token: DEFAULT.refreshToken,
              token_type: "Bearer",
              expires_in: 86400,
              scope: "openid profile email"
            });
          }
        )
      );

      const result = await authClient.passwordlessVerify({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      expect(capturedParams.get("grant_type")).toBe(
        "http://auth0.com/oauth/grant-type/passwordless/otp"
      );
      expect(capturedParams.get("realm")).toBe("email");
      expect(capturedParams.get("username")).toBe(DEFAULT.email);
      expect(capturedParams.get("otp")).toBe(DEFAULT.verificationCode);
      expect(capturedParams.get("connection")).toBeNull();
      expect(capturedParams.get("verification_code")).toBeNull();
      expect(capturedParams.get("phone_number")).toBeNull();
      expect(capturedParams.get("email")).toBeNull();

      expect(result.access_token).toBe(DEFAULT.accessToken);
      expect(result.refresh_token).toBe(DEFAULT.refreshToken);
      expect(result.token_type).toBe("Bearer");
      expect(result.expires_in).toBe(86400);
    });

    it("sends correct params for sms connection", async () => {
      let capturedParams: URLSearchParams = new URLSearchParams();

      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedParams = new URLSearchParams(await request.text());
            return HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400
            });
          }
        )
      );

      await authClient.passwordlessVerify({
        connection: "sms",
        phoneNumber: DEFAULT.phoneNumber,
        verificationCode: DEFAULT.verificationCode
      });

      expect(capturedParams.get("realm")).toBe("sms");
      expect(capturedParams.get("username")).toBe(DEFAULT.phoneNumber);
      expect(capturedParams.get("otp")).toBe(DEFAULT.verificationCode);
      expect(capturedParams.get("connection")).toBeNull();
      expect(capturedParams.get("verification_code")).toBeNull();
      expect(capturedParams.get("email")).toBeNull();
      expect(capturedParams.get("phone_number")).toBeNull();
    });

    it("capitalizes token_type in response", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "bearer", // lowercase from Auth0
            expires_in: 86400
          });
        })
      );

      const result = await authClient.passwordlessVerify({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      expect(result.token_type).toBe("Bearer");
    });

    it("throws PasswordlessVerifyError on invalid_grant", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Wrong email or verification code."
            },
            { status: 403 }
          );
        })
      );

      await expect(
        authClient.passwordlessVerify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: "wrong-code"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessVerifyError",
        error: "invalid_grant",
        error_description: "Wrong email or verification code."
      });
    });

    it("throws PasswordlessVerifyError on discovery failure", async () => {
      // Override discovery to fail
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => HttpResponse.error()
        )
      );

      // Fresh client so discovery cache is empty
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

      await expect(
        freshClient.passwordlessVerify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        })
      ).rejects.toMatchObject({
        name: "PasswordlessVerifyError",
        error: "discovery_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Route Handlers
  // ---------------------------------------------------------------------------

  describe("Route Handlers", () => {
    describe("POST /auth/passwordless/start", () => {
      it("returns 204 for valid email start (send: code)", async () => {
        server.use(
          http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
            HttpResponse.json({}, { status: 200 })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "code"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(204);
        // OTP flow: no transaction cookie needed
        expect(res.headers.get("set-cookie")).toBeNull();
      });

      it("returns 204 + Set-Cookie transaction state for magic link (send: link)", async () => {
        server.use(
          http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
            HttpResponse.json({}, { status: 200 })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "link"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(204);

        // Magic link requires a PKCE transaction cookie so /auth/callback can
        // complete the code exchange when the user clicks the emailed link.
        // Without this cookie the callback throws InvalidStateError.
        const setCookie = res.headers.get("set-cookie");
        expect(setCookie).toBeTruthy();
        // The transaction cookie name contains the state param and is HttpOnly
        expect(setCookie).toMatch(/HttpOnly/i);
      });

      it("magic link: authParams sent to Auth0 include PKCE and scope/audience from SDK config", async () => {
        let capturedBody: Record<string, unknown> = {};

        server.use(
          http.post(
            `https://${DEFAULT.domain}/passwordless/start`,
            async ({ request }) => {
              capturedBody = (await request.json()) as Record<string, unknown>;
              return HttpResponse.json({}, { status: 200 });
            }
          )
        );

        // Client with explicit scope + audience so we can verify they're forwarded
        const scopedSecret = await generateSecret(32);
        const scopedClient = new AuthClient({
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          appBaseUrl: DEFAULT.appBaseUrl,
          secret: scopedSecret,
          transactionStore: new TransactionStore({ secret: scopedSecret }),
          sessionStore: new StatelessSessionStore({ secret: scopedSecret }),
          routes: getDefaultRoutes(),
          authorizationParameters: {
            scope: "openid profile email",
            audience: "https://api.example.com"
          }
        });

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "link"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        await scopedClient.handler(req);

        // Auth0 /passwordless/start receives authParams with PKCE params,
        // scope and audience from SDK config — NOT arbitrary client-supplied values
        const authParams = capturedBody.authParams as Record<string, string>;
        expect(authParams).toBeDefined();
        expect(authParams.code_challenge).toBeTruthy();
        expect(authParams.code_challenge_method).toBe("S256");
        expect(authParams.state).toBeTruthy();
        expect(authParams.nonce).toBeTruthy();
        expect(authParams.redirect_uri).toContain("/auth/callback");
        expect(authParams.scope).toBe("openid profile email");
        expect(authParams.audience).toBe("https://api.example.com");
      });

      it("returns 204 for valid sms start", async () => {
        server.use(
          http.post(`https://${DEFAULT.domain}/passwordless/start`, () =>
            HttpResponse.json({}, { status: 200 })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "sms",
              phoneNumber: DEFAULT.phoneNumber
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(204);
      });

      it("forwards x-request-language header to Auth0 when language is provided", async () => {
        let capturedHeaders: Record<string, string> = {};

        server.use(
          http.post(
            `https://${DEFAULT.domain}/passwordless/start`,
            async ({ request }) => {
              capturedHeaders = Object.fromEntries(request.headers.entries());
              return HttpResponse.json({}, { status: 200 });
            }
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "code",
              language: "fr"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(204);
        expect(capturedHeaders["x-request-language"]).toBe("fr");
      });

      it("does not forward x-request-language when language is omitted", async () => {
        let capturedHeaders: Record<string, string> = {};

        server.use(
          http.post(
            `https://${DEFAULT.domain}/passwordless/start`,
            async ({ request }) => {
              capturedHeaders = Object.fromEntries(request.headers.entries());
              return HttpResponse.json({}, { status: 200 });
            }
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "code"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(204);
        expect(capturedHeaders["x-request-language"]).toBeUndefined();
      });

      it("returns 400 for missing connection field", async () => {
        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({ email: DEFAULT.email, send: "code" }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBeTruthy();
      });

      it("returns 400 for unknown connection value", async () => {
        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "whatsapp",
              phoneNumber: DEFAULT.phoneNumber
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBe("invalid_connection");
      });

      it("returns 400 with Auth0 error details on API failure", async () => {
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

        const req = new NextRequest(
          new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              send: "code"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBe("bad.connection");
        expect(body.error_description).toBe("Connection not found.");
      });
    });

    describe("POST /auth/passwordless/verify", () => {
      it("returns 400 for missing verificationCode", async () => {
        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBeTruthy();
      });

      it("returns 400 for unknown connection value", async () => {
        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "whatsapp",
              phoneNumber: DEFAULT.phoneNumber,
              verificationCode: DEFAULT.verificationCode
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBe("invalid_connection");
      });

      it("returns 403 with error details on invalid_grant from Auth0", async () => {
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

        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              verificationCode: "wrong-code"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(403);
        const body = await res.json();
        expect(body.error).toBe("invalid_grant");
        expect(body.error_description).toBe(
          "Wrong email or verification code."
        );
      });

      it("returns 403 with invalid_issuer when id_token iss does not match domain", async () => {
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
          http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
            HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              id_token: idToken
            })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              verificationCode: DEFAULT.verificationCode
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(403);
        const body = await res.json();
        expect(body.error).toBe("invalid_issuer");
      });

      it("returns 403 with invalid_audience when id_token aud does not include client_id", async () => {
        const idToken = await new jose.SignJWT({
          sub: DEFAULT.sub,
          sid: DEFAULT.sid
        })
          .setProtectedHeader({ alg: "RS256" })
          .setIssuer(`https://${DEFAULT.domain}`)
          .setAudience("different-client-id")
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(keyPair.privateKey);

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
            HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              id_token: idToken
            })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              verificationCode: DEFAULT.verificationCode
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(403);
        const body = await res.json();
        expect(body.error).toBe("invalid_audience");
      });

      it("returns 200 + Set-Cookie and creates session for email verify", async () => {
        const idToken = await generateIdToken({ email: DEFAULT.email });

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
            HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              scope: "openid profile email",
              id_token: idToken
            })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "email",
              email: DEFAULT.email,
              verificationCode: DEFAULT.verificationCode
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(200);
        expect((await res.json()).success).toBe(true);
        expect(res.headers.get("set-cookie")).toBeTruthy();
      });

      it("returns 200 + Set-Cookie for sms verify", async () => {
        const idToken = await generateIdToken();

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
            HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              id_token: idToken
            })
          )
        );

        const req = new NextRequest(
          new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              connection: "sms",
              phoneNumber: DEFAULT.phoneNumber,
              verificationCode: DEFAULT.verificationCode
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const res = await authClient.handler(req);
        expect(res.status).toBe(200);
        expect(res.headers.get("set-cookie")).toBeTruthy();
      });
    });
  });

  // ---------------------------------------------------------------------------
  // DPoP: nonce retry on passwordless verify
  // ---------------------------------------------------------------------------

  describe("DPoP-enabled passwordless verify", () => {
    it("retries with server-supplied nonce on use_dpop_nonce and sends DPoP proof on both attempts", async () => {
      const dpopKeyPair = await generateDpopKeyPair();
      const dpopSecret = await generateSecret(32);
      const dpopTransactionStore = new TransactionStore({ secret: dpopSecret });
      const dpopSessionStore = new StatelessSessionStore({
        secret: dpopSecret
      });

      const dpopClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: dpopSecret,
        transactionStore: dpopTransactionStore,
        sessionStore: dpopSessionStore,
        routes: getDefaultRoutes(),
        useDPoP: true,
        dpopKeyPair
      });

      const idToken = await generateIdToken({ email: DEFAULT.email });

      // Track each /oauth/token request so we can assert DPoP header presence
      // and nonce inclusion on the retry.
      const tokenRequests: Array<{ hasDPoP: boolean; dpopNonce?: string }> = [];
      let callCount = 0;

      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            callCount++;
            const dpopHeader = request.headers.get("dpop");
            let dpopNonce: string | undefined;

            if (dpopHeader) {
              try {
                // DPoP JWT: header.payload.signature — extract nonce from payload
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
              // First attempt: signal that a nonce is required
              return HttpResponse.json(
                {
                  error: "use_dpop_nonce",
                  error_description:
                    "Authorization server requires nonce in DPoP proof"
                },
                {
                  status: 400,
                  headers: { "dpop-nonce": "server-issued-nonce-abc" }
                }
              );
            }

            // Second attempt: return a valid token response
            return HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              scope: "openid profile email",
              id_token: idToken
            });
          }
        )
      );

      const result = await dpopClient.passwordlessVerify({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      // Two requests were made (initial + retry)
      expect(callCount).toBe(2);

      // Both requests carried a DPoP proof header
      expect(tokenRequests[0].hasDPoP).toBe(true);
      expect(tokenRequests[1].hasDPoP).toBe(true);

      // The retry included the server-issued nonce
      expect(tokenRequests[1].dpopNonce).toBe("server-issued-nonce-abc");

      // The response was successfully returned
      expect(result.access_token).toBe(DEFAULT.accessToken);
    });
  });

  // ---------------------------------------------------------------------------
  // Security: scope/audience injection via request body
  // ---------------------------------------------------------------------------

  describe("scope and audience injection prevention", () => {
    it("ignores scope and audience in the verify request body — uses SDK-configured values", async () => {
      let capturedParams = new URLSearchParams();

      // Configure global audience and narrow scope on the client
      const restrictedSecret = await generateSecret(32);
      const restrictedClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: restrictedSecret,
        transactionStore: new TransactionStore({ secret: restrictedSecret }),
        sessionStore: new StatelessSessionStore({ secret: restrictedSecret }),
        routes: getDefaultRoutes(),
        authorizationParameters: {
          scope: "openid profile",
          audience: "https://api.example.com"
        }
      });

      const idToken = await generateIdToken();

      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedParams = new URLSearchParams(await request.text());
            return HttpResponse.json({
              access_token: DEFAULT.accessToken,
              token_type: "Bearer",
              expires_in: 86400,
              id_token: idToken
            });
          }
        )
      );

      // Attacker sends extra fields hoping to override scope/audience
      const req = new NextRequest(
        new URL("/auth/passwordless/verify", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            connection: "email",
            email: DEFAULT.email,
            verificationCode: DEFAULT.verificationCode,
            scope: "openid admin:all",
            audience: "https://attacker.example.com"
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      await restrictedClient.handler(req);

      // SDK-configured scope and audience are sent — not the injected ones
      expect(capturedParams.get("scope")).toBe("openid profile");
      expect(capturedParams.get("audience")).toBe("https://api.example.com");
    });

    it("ignores authParams in the start request body — route handler does not forward it", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passwordless/start`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json({}, { status: 200 });
          }
        )
      );

      // Attacker sends authParams hoping to inject scope/redirect_uri
      const req = new NextRequest(
        new URL("/auth/passwordless/start", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            connection: "email",
            email: DEFAULT.email,
            send: "code",
            authParams: {
              scope: "admin",
              redirect_uri: "https://evil.example.com"
            }
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(204);

      // authParams from the request body must not appear in the Auth0 API call
      expect(capturedBody.authParams).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // MCD resolver mode: ServerPasswordlessClient routes to correct domain
  // ---------------------------------------------------------------------------

  describe("MCD resolver mode — ServerPasswordlessClient", () => {
    it("start(req, options) calls forRequest with request headers and URL", async () => {
      const mockPasswordlessStart = vi.fn().mockResolvedValue(undefined);
      const mockAuthClient = {
        passwordlessStart: mockPasswordlessStart
      } as any;
      const mockForRequest = vi.fn().mockResolvedValue(mockAuthClient);
      const mockProvider = {
        isResolverMode: true,
        forRequest: mockForRequest
      } as any;

      const passwordlessClient = new ServerPasswordlessClient(mockProvider);

      const req = new NextRequest(
        new URL("/auth/passwordless/start", "https://tenant-a.example.com"),
        {
          method: "POST",
          headers: { host: "tenant-a.example.com" }
        }
      );

      await passwordlessClient.start(req, {
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });

      // forRequest must receive the request headers and URL for MCD resolution
      expect(mockForRequest).toHaveBeenCalledWith(req.headers, req.nextUrl);

      // The resolved auth client must be used for the actual passwordless call
      expect(mockPasswordlessStart).toHaveBeenCalledWith({
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });
    });

    it("verify(req, res, options) calls forRequest with request headers and URL", async () => {
      const idToken = await generateIdToken();
      const mockTokenResponse = {
        access_token: DEFAULT.accessToken,
        token_type: "Bearer",
        expires_in: 86400,
        id_token: idToken
      };

      const mockPasswordlessVerify = vi
        .fn()
        .mockResolvedValue(mockTokenResponse);
      const mockCreateSession = vi.fn().mockResolvedValue(undefined);
      const mockAuthClient = {
        passwordlessVerify: mockPasswordlessVerify,
        createSessionFromPasswordlessVerify: mockCreateSession
      } as any;
      const mockForRequest = vi.fn().mockResolvedValue(mockAuthClient);
      const mockProvider = {
        isResolverMode: true,
        forRequest: mockForRequest
      } as any;

      const passwordlessClient = new ServerPasswordlessClient(mockProvider);

      const req = new NextRequest(
        new URL("/auth/passwordless/verify", "https://tenant-b.example.com"),
        {
          method: "POST",
          headers: { host: "tenant-b.example.com" }
        }
      );
      const res = new NextResponse();

      await passwordlessClient.verify(req, res, {
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      // forRequest must receive the request headers and URL for MCD resolution
      expect(mockForRequest).toHaveBeenCalledWith(req.headers, req.nextUrl);

      expect(mockPasswordlessVerify).toHaveBeenCalledWith({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      // Session creation must use the req/res cookies from the Pages Router call
      expect(mockCreateSession).toHaveBeenCalledWith(
        mockTokenResponse,
        req.cookies,
        res.cookies
      );
    });

    it("routes different host headers to different Auth0 domains", async () => {
      const domainARequests: string[] = [];
      const domainBRequests: string[] = [];

      // Register handlers for the two tenant domains on the shared global server.
      // setupMswLifecycle calls server.resetHandlers() after each test, so these
      // overrides are automatically cleaned up without manual teardown.
      server.use(
        http.get(
          "https://tenant-a.auth0.com/.well-known/openid-configuration",
          () =>
            HttpResponse.json(
              createAuthorizationServerMetadata("tenant-a.auth0.com")
            )
        ),
        http.post(
          "https://tenant-a.auth0.com/passwordless/start",
          async ({ request }) => {
            domainARequests.push(request.url);
            return HttpResponse.json({}, { status: 200 });
          }
        ),
        http.get(
          "https://tenant-b.auth0.com/.well-known/openid-configuration",
          () =>
            HttpResponse.json(
              createAuthorizationServerMetadata("tenant-b.auth0.com")
            )
        ),
        http.post(
          "https://tenant-b.auth0.com/passwordless/start",
          async ({ request }) => {
            domainBRequests.push(request.url);
            return HttpResponse.json({}, { status: 200 });
          }
        )
      );

      const sharedSecret = await generateSecret(32);

      // Resolver: maps host header to the correct Auth0 tenant domain
      const resolver = async ({ headers }: { headers: Headers }) => {
        const host = headers.get("host") ?? "";
        if (host === "tenant-a.example.com") return "tenant-a.auth0.com";
        if (host === "tenant-b.example.com") return "tenant-b.auth0.com";
        throw new Error(`Unknown host: ${host}`);
      };

      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: (domain) =>
          new AuthClient({
            domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,
            appBaseUrl: DEFAULT.appBaseUrl,
            secret: sharedSecret,
            transactionStore: new TransactionStore({ secret: sharedSecret }),
            sessionStore: new StatelessSessionStore({ secret: sharedSecret }),
            routes: getDefaultRoutes()
          })
      });

      const passwordlessClient = new ServerPasswordlessClient(provider);

      const reqA = new NextRequest(
        new URL("/auth/passwordless/start", "https://tenant-a.example.com"),
        { method: "POST", headers: { host: "tenant-a.example.com" } }
      );

      const reqB = new NextRequest(
        new URL("/auth/passwordless/start", "https://tenant-b.example.com"),
        { method: "POST", headers: { host: "tenant-b.example.com" } }
      );

      await passwordlessClient.start(reqA, {
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });

      await passwordlessClient.start(reqB, {
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });

      expect(domainARequests).toHaveLength(1);
      expect(domainBRequests).toHaveLength(1);
      expect(domainARequests[0]).toContain("tenant-a.auth0.com");
      expect(domainBRequests[0]).toContain("tenant-b.auth0.com");
    });
  });
});
