/**
 * Flow tests for AuthClient passkey route handlers.
 * Tests handlePasskeyRegister / handlePasskeyChallenge /
 * handlePasskeyGetToken via authClient.handler() — the full HTTP dispatch layer.
 *
 * Core AuthClient passkey method tests live in passkey.flow.test.ts.
 * ServerPasskeyClient (App/Pages Router overloads) is in
 * passkey/server-passkey-client.test.ts.
 */
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
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "passkeys|test-user-id",
  sid: "test-sid",
  authSession: "test-auth-session-token",
  accessToken: "test-access-token"
};

const MOCK_AUTH_RESPONSE = {
  id: "cred-id",
  rawId: "cred-raw-id",
  type: "public-key",
  response: {
    clientDataJSON: "clientDataJSON-base64url",
    attestationObject: "attestationObject-base64url"
  }
};

let keyPair: jose.GenerateKeyPairResult;

const authorizationServerMetadata = createAuthorizationServerMetadata(
  DEFAULT.domain
);

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json(authorizationServerMetadata)
  ),
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

describe("AuthClient passkey route handlers", () => {
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
  // POST /auth/passkey/register
  // ---------------------------------------------------------------------------

  describe("POST /auth/passkey/register", () => {
    it("returns 200 with challenge on success", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: { challenge: "signup-abc" }
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/register", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.authSession).toBe(DEFAULT.authSession);
      expect(body.authnParamsPublicKey).toEqual({ challenge: "signup-abc" });
    });

    it("forwards user_profile fields from request body", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passkey/register`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json({
              auth_session: DEFAULT.authSession,
              authn_params_public_key: {}
            });
          }
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/register", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ email: "jane@example.com", name: "Jane Doe" }),
          headers: { "Content-Type": "application/json" }
        }
      );

      await authClient.handler(req);
      expect(capturedBody.user_profile).toMatchObject({
        email: "jane@example.com",
        name: "Jane Doe"
      });
    });

    it("returns 400 with Auth0 error details on API failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.json(
            {
              error: "passkeys_not_enabled",
              error_description: "Passkeys are not enabled."
            },
            { status: 400 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/register", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("passkeys_not_enabled");
      expect(body.error_description).toBe("Passkeys are not enabled.");
    });

    it("returns 500 on unexpected_error", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.error()
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/register", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error).toBe("server_error");
    });
  });

  // ---------------------------------------------------------------------------
  // POST /auth/passkey/challenge
  // ---------------------------------------------------------------------------

  describe("POST /auth/passkey/challenge", () => {
    it("returns 200 with challenge on success", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
          HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: { challenge: "login-abc" }
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.authSession).toBe(DEFAULT.authSession);
      expect(body.authnParamsPublicKey).toEqual({ challenge: "login-abc" });
    });

    it("returns 400 with Auth0 error details on API failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
          HttpResponse.json(
            {
              error: "passkeys_not_enabled",
              error_description: "Passkeys are not enabled."
            },
            { status: 400 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("passkeys_not_enabled");
    });

    it("returns 500 on unexpected_error", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
          HttpResponse.error()
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/challenge", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error).toBe("server_error");
    });
  });

  // ---------------------------------------------------------------------------
  // POST /auth/passkey/get-token
  // ---------------------------------------------------------------------------

  describe("POST /auth/passkey/get-token", () => {
    it("returns 200 with session cookie on successful verify", async () => {
      const idToken = await new jose.SignJWT({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid
      })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer(`https://${DEFAULT.domain}`)
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
            scope: "openid profile email",
            id_token: idToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(res.headers.get("set-cookie")).toMatch(/__session=/);
    });

    it("returns 400 for missing authSession", async () => {
      const req = new NextRequest(
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ authResponse: MOCK_AUTH_RESPONSE }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBeTruthy();
    });

    it("returns 400 for missing authResponse", async () => {
      const req = new NextRequest(
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({ authSession: DEFAULT.authSession }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe("authResponse is required");
    });

    it("returns 403 with error details on invalid_grant from Auth0", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
          HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Invalid passkey assertion."
            },
            { status: 400 }
          )
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe("invalid_grant");
      expect(body.error_description).toBe("Invalid passkey assertion.");
    });

    it("returns 403 with invalid_issuer when id_token iss does not match domain", async () => {
      const wrongIdToken = await new jose.SignJWT({
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
            id_token: wrongIdToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await authClient.handler(req);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe("invalid_issuer");
    });

    it("returns 500 on discovery_error", async () => {
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
        new URL("/auth/passkey/get-token", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          }),
          headers: { "Content-Type": "application/json" }
        }
      );

      const res = await freshClient.handler(req);
      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error).toBe("server_error");
    });
  });
});
