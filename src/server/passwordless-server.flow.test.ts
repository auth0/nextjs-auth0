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
import type { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
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
      it("returns 204 for valid email start", async () => {
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
});
