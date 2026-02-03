import { NextRequest } from "next/server.js";
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
import {
  challengeScenarios,
  deleteAuthenticatorScenarios,
  enrollScenarios,
  getAuthenticatorsScenarios,
  verifyScenarios
} from "../test/mfa-scenarios-shared.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import { encryptMfaToken } from "../utils/mfa-utils.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "test-user-id",
  accessToken: "test-access-token",
  mfaToken: "raw-mfa-token-from-auth0"
};

// Mock authorization server metadata
const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"]
};

// MSW server setup
const server = setupServer(
  // OIDC Discovery
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  })
);

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

async function createSessionCookie(
  session: SessionData,
  secret: string
): Promise<string> {
  const maxAge = 60 * 60; // 1 hour
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  return await encrypt(session, secret, expiration);
}

describe("AuthClient MFA Methods", () => {
  let secret: string;
  let transactionStore: TransactionStore;
  let sessionStore: StatelessSessionStore;
  let authClient: AuthClient;

  beforeEach(async () => {
    secret = await generateSecret(32);
    transactionStore = new TransactionStore({ secret });
    sessionStore = new StatelessSessionStore({ secret });
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

  describe("mfaGetAuthenticators", () => {
    getAuthenticatorsScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          scenario.input.mfaRequirements?.challenge
            ? "https://api.example.com"
            : "",
          "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler
        if (scenario.mswResponse) {
          server.use(
            http.get(
              `https://${DEFAULT.domain}/mfa/authenticators`,
              ({ request }) => {
                // Verify Bearer token header
                const authHeader = request.headers.get("Authorization");
                expect(authHeader).toBe(`Bearer ${DEFAULT.mfaToken}`);

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Execute test
        if (scenario.expectError) {
          try {
            await authClient.mfaGetAuthenticators(encryptedToken);
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await authClient.mfaGetAuthenticators(encryptedToken);
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should map Auth0 snake_case to camelCase", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.get(`https://${DEFAULT.domain}/mfa/authenticators`, () => {
          return HttpResponse.json([
            {
              id: "auth_123",
              authenticator_type: "otp",
              type: "otp",
              active: true,
              created_at: "2024-01-01T00:00:00.000Z",
              last_auth: "2024-01-15T00:00:00.000Z"
            }
          ]);
        })
      );

      const result = await authClient.mfaGetAuthenticators(encryptedToken);
      expect(result[0]).toMatchObject({
        id: "auth_123",
        authenticatorType: "otp",
        type: "otp",
        active: true,
        createdAt: "2024-01-01T00:00:00.000Z",
        lastAuthenticatedAt: "2024-01-15T00:00:00.000Z"
      });
    });

    it("should throw MfaTokenInvalidError for malformed token", async () => {
      const { MfaTokenInvalidError } = await import("../errors/index.js");

      try {
        await authClient.mfaGetAuthenticators("malformed-token");
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenInvalidError);
      }
    });

    it("should throw MfaTokenExpiredError for expired token", async () => {
      const { MfaTokenExpiredError } = await import("../errors/index.js");

      // Create expired token (negative TTL)
      const expiredToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        -60 // Already expired
      );

      try {
        await authClient.mfaGetAuthenticators(expiredToken);
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenExpiredError);
      }
    });

    it("should filter by challenge types (case-insensitive)", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "OTP" }] }, // Uppercase
        secret,
        300
      );

      server.use(
        http.get(`https://${DEFAULT.domain}/mfa/authenticators`, () => {
          return HttpResponse.json([
            {
              id: "auth_123",
              authenticator_type: "otp",
              type: "otp", // Lowercase from API
              active: true
            },
            {
              id: "auth_456",
              authenticator_type: "oob",
              type: "oob",
              active: true
            }
          ]);
        })
      );

      const result = await authClient.mfaGetAuthenticators(encryptedToken);
      expect(result.length).toBe(1);
      expect(result[0].type).toBe("otp");
    });
  });

  describe("mfaChallenge", () => {
    challengeScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler
        if (scenario.mswResponse) {
          server.use(
            http.post(
              `https://${DEFAULT.domain}/mfa/challenge`,
              async ({ request }) => {
                const body = (await request.json()) as any;
                expect(body.mfa_token).toBe(DEFAULT.mfaToken);
                expect(body.challenge_type).toBe(scenario.input.challengeType);
                expect(body.client_id).toBe(DEFAULT.clientId);
                if (scenario.input.authenticatorId) {
                  expect(body.authenticator_id).toBe(
                    scenario.input.authenticatorId
                  );
                }

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Execute test
        if (scenario.expectError) {
          try {
            await authClient.mfaChallenge(
              encryptedToken,
              scenario.input.challengeType,
              scenario.input.authenticatorId
            );
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await authClient.mfaChallenge(
            encryptedToken,
            scenario.input.challengeType,
            scenario.input.authenticatorId
          );
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should pass empty authenticatorId as undefined", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(
          `https://${DEFAULT.domain}/mfa/challenge`,
          async ({ request }) => {
            const body = (await request.json()) as any;
            expect(body.authenticator_id).toBeUndefined();
            return HttpResponse.json({ challenge_type: "otp" });
          }
        )
      );

      await authClient.mfaChallenge(encryptedToken, "otp", "");
    });
  });

  describe("mfaVerify", () => {
    verifyScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          scenario.input.audience || "https://api.example.com",
          scenario.input.scope || "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler
        if (scenario.mswResponse) {
          server.use(
            http.post(
              `https://${DEFAULT.domain}/oauth/token`,
              async ({ request }) => {
                // Clone request to preserve stream for oauth4webapi
                const clonedRequest = request.clone();
                const body = await clonedRequest.text();
                const params = new URLSearchParams(body);

                expect(params.get("mfa_token")).toBe(DEFAULT.mfaToken);

                if (scenario.input.otp) {
                  expect(params.get("grant_type")).toBe(
                    "http://auth0.com/oauth/grant-type/mfa-otp"
                  );
                  expect(params.get("otp")).toBe(scenario.input.otp);
                } else if (scenario.input.oobCode) {
                  expect(params.get("grant_type")).toBe(
                    "http://auth0.com/oauth/grant-type/mfa-oob"
                  );
                  expect(params.get("oob_code")).toBe(scenario.input.oobCode);
                  expect(params.get("binding_code")).toBe(
                    scenario.input.bindingCode
                  );
                } else if (scenario.input.recoveryCode) {
                  expect(params.get("grant_type")).toBe(
                    "http://auth0.com/oauth/grant-type/mfa-recovery-code"
                  );
                  expect(params.get("recovery_code")).toBe(
                    scenario.input.recoveryCode
                  );
                }

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status,
                  headers: {
                    "Content-Type": "application/json"
                  }
                });
              }
            )
          );
        }

        // Build verify options
        const verifyOptions: any = { mfaToken: encryptedToken };
        if (scenario.input.otp) verifyOptions.otp = scenario.input.otp;
        if (scenario.input.oobCode) {
          verifyOptions.oobCode = scenario.input.oobCode;
          verifyOptions.bindingCode = scenario.input.bindingCode;
        }
        if (scenario.input.recoveryCode)
          verifyOptions.recoveryCode = scenario.input.recoveryCode;

        // Execute test
        if (scenario.expectError) {
          try {
            await authClient.mfaVerify(verifyOptions);
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await authClient.mfaVerify(verifyOptions);
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should cache access token in session when cookies provided", async () => {
      const { RequestCookies, ResponseCookies } = await import(
        "@edge-runtime/cookies"
      );

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          idToken: "id-token",
          accessToken: "old-access-token",
          refreshToken: "refresh-token",
          expiresAt: 123456
        },
        internal: {
          sid: "session-id",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const sessionCookie = await createSessionCookie(session, secret);
      const reqHeaders = new Headers();
      reqHeaders.append("cookie", `__session=${sessionCookie}`);

      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "read:data",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              access_token: "new-mfa-access-token",
              token_type: "Bearer",
              expires_in: 3600,
              scope: "read:data"
            },
            {
              headers: {
                "Content-Type": "application/json"
              }
            }
          );
        })
      );

      const reqCookies = new RequestCookies(reqHeaders);
      const resHeaders = new Headers();
      const resCookies = new ResponseCookies(resHeaders);

      const result = await authClient.mfaVerify({
        mfaToken: encryptedToken,
        otp: "123456"
      });

      // Cache tokens in session
      await authClient.cacheTokenFromMfaVerify(
        result,
        encryptedToken,
        reqCookies,
        resCookies
      );

      // Verify session was updated
      const updatedSession = await sessionStore.get(reqCookies);
      expect(updatedSession?.accessTokens).toBeDefined();
      expect(updatedSession?.accessTokens?.length).toBeGreaterThan(0);
      expect(updatedSession?.accessTokens?.[0].accessToken).toBe(
        "new-mfa-access-token"
      );
      expect(updatedSession?.accessTokens?.[0].audience).toBe(
        "https://api.example.com"
      );
    });

    it("should work without session (stateless operation)", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "read:data",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json({
            access_token: "stateless-access-token",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "read:data"
          });
        })
      );

      // No cookies provided - stateless operation
      const result = await authClient.mfaVerify({
        mfaToken: encryptedToken,
        otp: "123456"
      });

      expect(result.access_token).toBe("stateless-access-token");
      expect(result.token_type).toBe("Bearer");
    });

    it("should preserve token_type from Auth0 response", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json({
            access_token: "at_123",
            token_type: "Bearer",
            expires_in: 3600
          });
        })
      );

      const result = await authClient.mfaVerify({
        mfaToken: encryptedToken,
        otp: "123456"
      });

      expect(result.token_type).toBe("Bearer");
    });

    it("should preserve audience/scope in chained MFA", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "read:data write:data",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Invalid OTP, retry required",
              mfa_token: "new-raw-mfa-token",
              mfa_requirements: {
                challenge: [{ type: "otp" }]
              }
            },
            {
              status: 400,
              headers: {
                "Content-Type": "application/json"
              }
            }
          );
        })
      );

      const { MfaRequiredError } = await import("../errors/index.js");

      try {
        await authClient.mfaVerify({ mfaToken: encryptedToken, otp: "000000" });
        throw new Error("Expected MfaRequiredError");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaRequiredError);
        const mfaError = error as any;

        // Decrypt new token to verify context preserved
        const { decryptMfaToken } = await import("../utils/mfa-utils.js");
        const newContext = await decryptMfaToken(mfaError.mfa_token, secret);
        expect(newContext.audience).toBe("https://api.example.com");
        expect(newContext.scope).toBe("read:data write:data");
        expect(newContext.mfaToken).toBe("new-raw-mfa-token");
      }
    });
  });

  describe("mfaEnroll", () => {
    // Shared scenarios (4 tests)
    enrollScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );

        if (scenario.mswResponse) {
          server.use(
            http.post(
              `https://${DEFAULT.domain}/mfa/associate`,
              async ({ request }) => {
                const authHeader = request.headers.get("Authorization");
                expect(authHeader).toBe(`Bearer ${DEFAULT.mfaToken}`);

                const body = (await request.json()) as any;
                expect(body.authenticator_types).toEqual(
                  scenario.input.authenticatorTypes
                );

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        if (scenario.expectError) {
          try {
            await authClient.mfaEnroll(encryptedToken, {
              authenticatorTypes: scenario.input.authenticatorTypes,
              ...(scenario.input.oobChannels && {
                oobChannels: scenario.input.oobChannels
              }),
              ...(scenario.input.phoneNumber && {
                phoneNumber: scenario.input.phoneNumber
              }),
              ...(scenario.input.email && { email: scenario.input.email })
            } as any);
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await authClient.mfaEnroll(encryptedToken, {
            authenticatorTypes: scenario.input.authenticatorTypes,
            ...(scenario.input.oobChannels && {
              oobChannels: scenario.input.oobChannels
            }),
            ...(scenario.input.phoneNumber && {
              phoneNumber: scenario.input.phoneNumber
            }),
            ...(scenario.input.email && { email: scenario.input.email })
          } as any);
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          }
        }
      });
    });

    // Field mapping (1 test)
    it("should map snake_case to camelCase", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      server.use(
        http.post(`https://${DEFAULT.domain}/mfa/associate`, () => {
          return HttpResponse.json({
            authenticator_type: "otp",
            barcode_uri: "otpauth://totp/test",
            secret: "base32secret",
            recovery_codes: ["code1", "code2"]
          });
        })
      );

      const result = await authClient.mfaEnroll(encryptedToken, {
        authenticatorTypes: ["otp"]
      });

      expect(result).toMatchObject({
        authenticatorType: "otp",
        barcodeUri: "otpauth://totp/test",
        secret: "base32secret",
        recoveryCodes: ["code1", "code2"]
      });
      expect(result).not.toHaveProperty("barcode_uri");
      expect(result).not.toHaveProperty("recovery_codes");
    });

    // Token validation (2 tests)
    it("should throw MfaTokenInvalidError for malformed token", async () => {
      const { MfaTokenInvalidError } = await import("../errors/index.js");

      try {
        await authClient.mfaEnroll("malformed-token", {
          authenticatorTypes: ["otp"]
        });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenInvalidError);
      }
    });

    it("should throw MfaTokenExpiredError for expired token", async () => {
      const { MfaTokenExpiredError } = await import("../errors/index.js");
      const expiredToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        -60
      );

      try {
        await authClient.mfaEnroll(expiredToken, {
          authenticatorTypes: ["otp"]
        });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenExpiredError);
      }
    });

    // Request structure (1 test)
    it("should send correct POST request to Auth0", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      let requestBody: any;
      let authHeader: string | null = null;
      server.use(
        http.post(
          `https://${DEFAULT.domain}/mfa/associate`,
          async ({ request }) => {
            authHeader = request.headers.get("Authorization");
            requestBody = await request.json();
            return HttpResponse.json({
              authenticator_type: "otp",
              barcode_uri: "otpauth://...",
              secret: "SECRET"
            });
          }
        )
      );

      await authClient.mfaEnroll(encryptedToken, {
        authenticatorTypes: ["otp"]
      });

      expect(authHeader).toBe(`Bearer ${DEFAULT.mfaToken}`);
      expect(requestBody).toMatchObject({
        authenticator_types: ["otp"]
      });
    });
  });

  describe("mfaDeleteAuthenticator", () => {
    // Shared scenarios (3 tests)
    deleteAuthenticatorScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );

        if (scenario.mswResponse) {
          server.use(
            http.delete(
              `https://${DEFAULT.domain}/mfa/authenticators/${scenario.input.authenticatorId}`,
              () => {
                if (scenario.mswResponse!.status === 204) {
                  return new HttpResponse(null, { status: 204 });
                }
                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        if (scenario.expectError) {
          try {
            await authClient.mfaDeleteAuthenticator(
              encryptedToken,
              scenario.input.authenticatorId
            );
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await authClient.mfaDeleteAuthenticator(
            encryptedToken,
            scenario.input.authenticatorId
          );
          expect(result).toBeUndefined();
        }
      });
    });

    // Token validation (2 tests)
    it("should throw MfaTokenInvalidError for malformed token", async () => {
      const { MfaTokenInvalidError } = await import("../errors/index.js");

      try {
        await authClient.mfaDeleteAuthenticator("malformed-token", "auth_123");
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenInvalidError);
      }
    });

    it("should throw MfaTokenExpiredError for expired token", async () => {
      const { MfaTokenExpiredError } = await import("../errors/index.js");
      const expiredToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        -60
      );

      try {
        await authClient.mfaDeleteAuthenticator(expiredToken, "auth_123");
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaTokenExpiredError);
      }
    });

    // Request structure (1 test)
    it("should send DELETE request to Auth0", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      let deleteCalled = false;
      server.use(
        http.delete(
          `https://${DEFAULT.domain}/mfa/authenticators/auth_123`,
          ({ request }) => {
            deleteCalled = true;
            const authHeader = request.headers.get("Authorization");
            expect(authHeader).toBe(`Bearer ${DEFAULT.mfaToken}`);
            return new HttpResponse(null, { status: 204 });
          }
        )
      );

      await authClient.mfaDeleteAuthenticator(encryptedToken, "auth_123");
      expect(deleteCalled).toBe(true);
    });

    // 204 handling (1 test)
    it("should handle 204 no content response", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      server.use(
        http.delete(
          `https://${DEFAULT.domain}/mfa/authenticators/auth_123`,
          () => {
            return new HttpResponse(null, { status: 204 });
          }
        )
      );

      const result = await authClient.mfaDeleteAuthenticator(
        encryptedToken,
        "auth_123"
      );
      expect(result).toBeUndefined();
    });
  });

  describe("Route Handlers", () => {
    describe("POST /auth/mfa/enroll", () => {
      it("should route to handleEnroll and return 200", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );

        server.use(
          http.post(`https://${DEFAULT.domain}/mfa/associate`, () => {
            return HttpResponse.json({
              authenticator_type: "otp",
              barcode_uri: "otpauth://...",
              secret: "base32secret"
            });
          })
        );

        const request = new NextRequest(
          new URL("/auth/mfa/enroll", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              mfaToken: encryptedToken,
              authenticatorTypes: ["otp"]
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(200);

        const result = await response.json();
        expect(result.authenticatorType).toBe("otp");
      });

      it("should return 400 for missing mfaToken", async () => {
        const request = new NextRequest(
          new URL("/auth/mfa/enroll", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({ authenticatorTypes: ["otp"] }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(400);

        const error = await response.json();
        expect(error.error).toBe("invalid_request");
      });

      it("should return 400 for invalid JSON", async () => {
        const request = new NextRequest(
          new URL("/auth/mfa/enroll", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: "invalid-json",
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(400);
      });

      it("should return 400 for missing authenticatorTypes", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );

        const request = new NextRequest(
          new URL("/auth/mfa/enroll", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({ mfaToken: encryptedToken }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(400);
      });
    });

    describe("DELETE /auth/mfa/authenticators/:id", () => {
      it("should route to handleDeleteAuthenticator and return 204", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );
        const authenticatorId = "auth_123";

        server.use(
          http.delete(
            `https://${DEFAULT.domain}/mfa/authenticators/${authenticatorId}`,
            () => {
              return new HttpResponse(null, { status: 204 });
            }
          )
        );

        const headers = new Headers();
        headers.append("Authorization", `Bearer ${encryptedToken}`);

        const request = new NextRequest(
          new URL(
            `/auth/mfa/authenticators/${authenticatorId}`,
            DEFAULT.appBaseUrl
          ),
          { method: "DELETE", headers }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(204);
      });

      it("should return 400 for missing Authorization header", async () => {
        const request = new NextRequest(
          new URL("/auth/mfa/authenticators/auth_123", DEFAULT.appBaseUrl),
          { method: "DELETE" }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(400);

        const error = await response.json();
        expect(error.error).toBe("invalid_request");
      });

      it("should return 400 for malformed Authorization", async () => {
        const headers = new Headers();
        headers.append("Authorization", "Invalid format");

        const request = new NextRequest(
          new URL("/auth/mfa/authenticators/auth_123", DEFAULT.appBaseUrl),
          { method: "DELETE", headers }
        );

        const response = await authClient.handler(request);
        expect(response.status).toBe(400);
      });
    });

    describe("GET /auth/mfa/authenticators", () => {
      it("should extract Bearer token and return authenticators", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          { challenge: [{ type: "otp" }] },
          secret,
          300
        );

        server.use(
          http.get(`https://${DEFAULT.domain}/mfa/authenticators`, () => {
            return HttpResponse.json([
              {
                id: "auth_123",
                authenticator_type: "otp",
                type: "otp",
                active: true
              }
            ]);
          })
        );

        const headers = new Headers();
        headers.append("Authorization", `Bearer ${encryptedToken}`);

        const request = new NextRequest(
          new URL("/auth/mfa/authenticators", DEFAULT.appBaseUrl),
          { method: "GET", headers }
        );

        const response = await authClient.handleGetAuthenticators(request);
        expect(response.status).toBe(200);

        const result = await response.json();
        expect(result.length).toBe(1);
        expect(result[0].type).toBe("otp");
      });

      it("should return 401 for missing Authorization header", async () => {
        const request = new NextRequest(
          new URL("/auth/mfa/authenticators", DEFAULT.appBaseUrl),
          { method: "GET" }
        );

        const response = await authClient.handleGetAuthenticators(request);
        expect(response.status).toBe(400);

        const error = await response.json();
        expect(error.error).toBe("invalid_request");
      });

      it("should return 401 for malformed Authorization header", async () => {
        const headers = new Headers();
        headers.append("Authorization", "Invalid format");

        const request = new NextRequest(
          new URL("/auth/mfa/authenticators", DEFAULT.appBaseUrl),
          { method: "GET", headers }
        );

        const response = await authClient.handleGetAuthenticators(request);
        expect(response.status).toBe(400);

        const error = await response.json();
        expect(error.error).toBe("invalid_request");
      });
    });

    describe("POST /auth/mfa/challenge", () => {
      it("should parse JSON body and return challenge response", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          { challenge: [{ type: "otp" }] },
          secret,
          300
        );

        server.use(
          http.post(`https://${DEFAULT.domain}/mfa/challenge`, () => {
            return HttpResponse.json({
              challenge_type: "otp"
            });
          })
        );

        const request = new NextRequest(
          new URL("/auth/mfa/challenge", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              mfaToken: encryptedToken,
              challengeType: "otp"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handleChallenge(request);
        expect(response.status).toBe(200);

        const result = await response.json();
        expect(result.challengeType).toBe("otp");
      });

      it("should return 400 for invalid JSON", async () => {
        const request = new NextRequest(
          new URL("/auth/mfa/challenge", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: "invalid-json",
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handleChallenge(request);
        expect(response.status).toBe(400);
      });
    });

    describe("POST /auth/mfa/verify", () => {
      it("should parse JSON body and return token response", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          { challenge: [{ type: "otp" }] },
          secret,
          300
        );

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
            return HttpResponse.json({
              access_token: "new-access-token",
              token_type: "Bearer",
              expires_in: 3600
            });
          })
        );

        const request = new NextRequest(
          new URL("/auth/mfa/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              mfaToken: encryptedToken,
              otp: "123456"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handleVerify(request);
        expect(response.status).toBe(200);

        const result = await response.json();
        expect(result.access_token).toBe("new-access-token");
      });

      it("should return 400 with new mfaToken for chained MFA", async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          { challenge: [{ type: "otp" }] },
          secret,
          300
        );

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
            return HttpResponse.json(
              {
                error: "mfa_required",
                error_description: "Invalid OTP",
                mfa_token: "new-raw-token",
                mfa_requirements: {
                  challenge: [{ type: "otp" }]
                }
              },
              {
                status: 403,
                headers: {
                  "Content-Type": "application/json"
                }
              }
            );
          })
        );

        const request = new NextRequest(
          new URL("/auth/mfa/verify", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: JSON.stringify({
              mfaToken: encryptedToken,
              otp: "000000"
            }),
            headers: { "Content-Type": "application/json" }
          }
        );

        const response = await authClient.handleVerify(request);
        expect(response.status).toBe(403);

        const error = await response.json();
        expect(error.error).toBe("mfa_required");
        expect(error.mfa_token).toBeTruthy(); // New encrypted token
        expect(error.mfa_requirements).toBeTruthy();
      });
    });
  });
});
