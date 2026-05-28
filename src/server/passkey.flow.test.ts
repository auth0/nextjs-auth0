/**
 * Flow tests for AuthClient passkey core methods.
 * Tests the raw AuthClient.passkeyRegister / passkeyChallenge /
 * passkeyGetToken methods — no Next.js runtime or cookie layer involved.
 *
 * The route handler and ServerPasskeyClient layers are tested in
 * passkey-server.flow.test.ts and passkey/server-passkey-client.test.ts.
 */
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
  sub: "passkeys|test-user-id",
  sid: "test-sid",
  authSession: "test-auth-session-token",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token"
};

const MOCK_AUTH_RESPONSE = {
  id: "cred-id",
  rawId: "cred-raw-id",
  type: "public-key" as const,
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

describe("AuthClient passkey methods", () => {
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
  // passkeyRegister
  // ---------------------------------------------------------------------------

  describe("passkeyRegister", () => {
    it("sends client_id and client_secret in request body", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passkey/register`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json({
              auth_session: DEFAULT.authSession,
              authn_params_public_key: { challenge: "abc" }
            });
          }
        )
      );

      await authClient.passkeyRegister();

      expect(capturedBody.client_id).toBe(DEFAULT.clientId);
      expect(capturedBody.client_secret).toBe(DEFAULT.clientSecret);
      expect(capturedBody.user_display_name).toBeUndefined();
    });

    it("includes user_display_name when provided", async () => {
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

      await authClient.passkeyRegister({
        email: "jane@example.com",
        name: "Jane Doe"
      });

      expect(capturedBody.user_profile).toMatchObject({
        email: "jane@example.com",
        name: "Jane Doe"
      });
    });

    it("places user_metadata at top level, not inside user_profile", async () => {
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

      await authClient.passkeyRegister({
        email: "jane@example.com",
        userMetadata: { plan: "pro" }
      });

      expect(capturedBody.user_metadata).toEqual({ plan: "pro" });
      expect(
        (capturedBody.user_profile as Record<string, unknown>).user_metadata
      ).toBeUndefined();
    });

    it("maps snake_case response to camelCase SDK shape", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: {
              rp: { id: "example.com" },
              challenge: "xyz"
            }
          })
        )
      );

      const result = await authClient.passkeyRegister();

      expect(result.authSession).toBe(DEFAULT.authSession);
      expect(result.authnParamsPublicKey).toEqual({
        rp: { id: "example.com" },
        challenge: "xyz"
      });
    });

    it("throws PasskeyRegisterError on Auth0 API error", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.json(
            {
              error: "passkeys_not_enabled",
              error_description:
                "Passkeys are not enabled for this application."
            },
            { status: 400 }
          )
        )
      );

      await expect(authClient.passkeyRegister()).rejects.toMatchObject({
        name: "PasskeyRegisterError",
        error: "passkeys_not_enabled",
        error_description: "Passkeys are not enabled for this application."
      });
    });

    it("throws PasskeyRegisterError with unexpected_error on network failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
          HttpResponse.error()
        )
      );

      await expect(authClient.passkeyRegister()).rejects.toMatchObject({
        name: "PasskeyRegisterError",
        error: "unexpected_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // passkeyChallenge
  // ---------------------------------------------------------------------------

  describe("passkeyChallenge", () => {
    it("sends client_id and client_secret in request body", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(
          `https://${DEFAULT.domain}/passkey/challenge`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json({
              auth_session: DEFAULT.authSession,
              authn_params_public_key: {}
            });
          }
        )
      );

      await authClient.passkeyChallenge();

      expect(capturedBody.client_id).toBe(DEFAULT.clientId);
      expect(capturedBody.client_secret).toBe(DEFAULT.clientSecret);
      expect(capturedBody.username).toBeUndefined();
    });

    it("maps snake_case response to camelCase SDK shape", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
          HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: { challenge: "login-xyz", timeout: 60000 }
          })
        )
      );

      const result = await authClient.passkeyChallenge();

      expect(result.authSession).toBe(DEFAULT.authSession);
      expect(result.authnParamsPublicKey).toEqual({
        challenge: "login-xyz",
        timeout: 60000
      });
    });

    it("throws PasskeyChallengeError on Auth0 API error", async () => {
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

      await expect(authClient.passkeyChallenge()).rejects.toMatchObject({
        name: "PasskeyChallengeError",
        error: "passkeys_not_enabled",
        error_description: "Passkeys are not enabled."
      });
    });

    it("throws PasskeyChallengeError with unexpected_error on network failure", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
          HttpResponse.error()
        )
      );

      await expect(authClient.passkeyChallenge()).rejects.toMatchObject({
        name: "PasskeyChallengeError",
        error: "unexpected_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // passkeyGetToken
  // ---------------------------------------------------------------------------

  describe("passkeyGetToken", () => {
    it("sends auth_session and authn_response to /oauth/token", async () => {
      let capturedBody: Record<string, unknown> = {};

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
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, unknown>;
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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resHeaders = new Headers();
      const resCookies = new ResponseCookies(resHeaders);

      await authClient.passkeyGetToken(
        { authSession: DEFAULT.authSession, authResponse: MOCK_AUTH_RESPONSE },
        reqCookies,
        resCookies
      );

      expect(capturedBody.auth_session).toBe(DEFAULT.authSession);
      expect(capturedBody.authn_response).toBeTruthy();
      expect(String(capturedBody.grant_type)).toContain("webauthn");
      // Session cookie written to resCookies
      expect(resHeaders.get("set-cookie")).toMatch(/__session=/);
    });

    it("throws PasskeyGetTokenError on invalid_grant from Auth0", async () => {
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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());

      await expect(
        authClient.passkeyGetToken(
          {
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          },
          reqCookies,
          resCookies
        )
      ).rejects.toMatchObject({
        name: "PasskeyGetTokenError",
        error: "invalid_grant",
        error_description: "Invalid passkey assertion."
      });
    });

    it("does not send a DPoP header when useDPoP is not configured", async () => {
      let capturedDpopHeader: string | null = null;

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
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedDpopHeader = request.headers.get("dpop");
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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());

      await authClient.passkeyGetToken(
        { authSession: DEFAULT.authSession, authResponse: MOCK_AUTH_RESPONSE },
        reqCookies,
        resCookies
      );

      expect(capturedDpopHeader).toBeNull();
    });

    it("sends a DPoP proof header when useDPoP is true", async () => {
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

      let capturedDpopHeader: string | null = null;

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
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            capturedDpopHeader = request.headers.get("dpop");
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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());

      await dpopClient.passkeyGetToken(
        { authSession: DEFAULT.authSession, authResponse: MOCK_AUTH_RESPONSE },
        reqCookies,
        resCookies
      );

      expect(capturedDpopHeader).not.toBeNull();

      // Verify the DPoP JWT structure: header.payload.signature
      const [, payloadB64] = capturedDpopHeader!.split(".");
      const payload = JSON.parse(
        Buffer.from(payloadB64, "base64url").toString()
      );
      expect(payload.htm).toBe("POST");
      expect(payload.htu).toBe(`https://${DEFAULT.domain}/oauth/token`);
      expect(payload.iat).toBeDefined();
      expect(payload.jti).toBeDefined();
    });

    it("retries with server-supplied nonce on use_dpop_nonce and includes nonce on second attempt", async () => {
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
                  headers: { "dpop-nonce": "server-issued-nonce-xyz" }
                }
              );
            }

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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());

      await dpopClient.passkeyGetToken(
        { authSession: DEFAULT.authSession, authResponse: MOCK_AUTH_RESPONSE },
        reqCookies,
        resCookies
      );

      // Two requests: initial attempt + nonce retry
      expect(callCount).toBe(2);

      // Both carried a DPoP proof
      expect(tokenRequests[0].hasDPoP).toBe(true);
      expect(tokenRequests[1].hasDPoP).toBe(true);

      // First attempt had no nonce (server hadn't issued one yet)
      expect(tokenRequests[0].dpopNonce).toBeUndefined();

      // Retry included the server-issued nonce
      expect(tokenRequests[1].dpopNonce).toBe("server-issued-nonce-xyz");
    });

    it("throws PasskeyGetTokenError on discovery failure", async () => {
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

      const { RequestCookies, ResponseCookies } =
        await import("@edge-runtime/cookies");
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());

      await expect(
        freshClient.passkeyGetToken(
          {
            authSession: DEFAULT.authSession,
            authResponse: MOCK_AUTH_RESPONSE
          },
          reqCookies,
          resCookies
        )
      ).rejects.toMatchObject({
        name: "PasskeyGetTokenError",
        error: "discovery_error"
      });
    });
  });
});
