import { NextRequest } from "next/server.js";
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
  it
} from "vitest";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode,
  MfaRequiredError
} from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { TOKEN_TYPES } from "../types/token-vault.js";
import { generateDpopKeyPair } from "../utils/dpopRetry.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

/**
 * Custom Token Exchange Test Suite
 *
 * Tests the customTokenExchange() method following the same MSW-based
 * black-box flow testing pattern as proxy-handler.test.ts.
 *
 * Test Categories:
 * 1: Validation Tests (subjectToken, subjectTokenType, actorToken)
 * 2: Successful Exchange Flows
 * 3: DPoP Integration
 * 4: Error Handling
 */

const DEFAULT = {
  domain: "test.auth0.local",
  clientId: "test_client_id",
  clientSecret: "test_client_secret",
  appBaseUrl: "https://example.com",
  sub: "user_test_123",
  sid: "session_test_123",
  alg: "RS256" as const
};

// Discovery metadata
const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  dpop_signing_alg_values_supported: ["RS256", "ES256"]
};

let keyPair: jose.GenerateKeyPairResult;
let secret: string;
let authClient: AuthClient;

// Token endpoint handler state for DPoP nonce retry tests
let dpopNonceState = { requireNonce: false, nonce: "" };

const server = setupServer(
  // Discovery endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  }),

  // JWKS endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-1", alg: DEFAULT.alg, use: "sig" }]
    });
  }),

  // Token endpoint - default handler for successful exchanges
  http.post(`https://${DEFAULT.domain}/oauth/token`, async ({ request }) => {
    const body = await request.text();
    const params = new URLSearchParams(body);

    // Verify grant type
    const grantType = params.get("grant_type");
    if (grantType !== "urn:ietf:params:oauth:grant-type:token-exchange") {
      return HttpResponse.json(
        {
          error: "unsupported_grant_type",
          error_description: "Invalid grant type"
        },
        { status: 400 }
      );
    }

    // Check DPoP nonce requirement
    if (dpopNonceState.requireNonce) {
      const dpopHeader = request.headers.get("DPoP");
      if (dpopHeader) {
        // Parse and check if nonce is present
        const parts = dpopHeader.split(".");
        if (parts.length === 3) {
          const payload = JSON.parse(atob(parts[1]));
          if (!payload.nonce) {
            dpopNonceState.nonce = "test-dpop-nonce-" + Date.now();
            return HttpResponse.json(
              {
                error: "use_dpop_nonce",
                error_description: "DPoP nonce required"
              },
              {
                status: 400,
                headers: { "DPoP-Nonce": dpopNonceState.nonce }
              }
            );
          }
        }
      }
    }

    // Generate ID token
    const jwt = await new jose.SignJWT({
      sid: DEFAULT.sid,
      auth_time: Math.floor(Date.now() / 1000),
      nonce: "nonce-value"
    })
      .setProtectedHeader({ alg: DEFAULT.alg })
      .setSubject(DEFAULT.sub)
      .setIssuedAt()
      .setIssuer(authorizationServerMetadata.issuer)
      .setAudience(DEFAULT.clientId)
      .setExpirationTime("2h")
      .sign(keyPair.privateKey);

    // Check if DPoP was used
    const dpopHeader = request.headers.get("DPoP");
    const tokenType = dpopHeader ? "DPoP" : "Bearer";

    return HttpResponse.json({
      token_type: tokenType,
      access_token: "at_cte_test_" + Date.now(),
      refresh_token: "rt_cte_test_" + Date.now(),
      id_token: jwt,
      expires_in: 3600,
      scope: params.get("scope") || "openid profile email offline_access"
    });
  })
);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair(DEFAULT.alg);
  secret = await generateSecret(32);
  server.listen({ onUnhandledRequest: "error" });
});

afterAll(() => {
  server.close();
});

beforeEach(async () => {
  dpopNonceState = { requireNonce: false, nonce: "" };

  const transactionStore = new TransactionStore({ secret });
  const sessionStore = new StatelessSessionStore({ secret });

  authClient = new AuthClient({
    transactionStore,
    sessionStore,
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    secret,
    appBaseUrl: DEFAULT.appBaseUrl,
    routes: getDefaultRoutes()
  });
});

afterEach(() => {
  server.resetHandlers();
});

describe("Custom Token Exchange", () => {
  describe("1: Validation Tests", () => {
    describe("subjectToken validation", () => {
      it("should return MISSING_SUBJECT_TOKEN error for empty string", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "",
          subjectTokenType: "urn:acme:legacy-token"
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN
        );
        expect(error?.message).toContain("required");
        expect(response).toBeNull();
      });

      it("should return MISSING_SUBJECT_TOKEN error for whitespace-only string", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "   ",
          subjectTokenType: "urn:acme:legacy-token"
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN
        );
        expect(response).toBeNull();
      });
    });

    describe("subjectTokenType validation", () => {
      it("should return INVALID_SUBJECT_TOKEN_TYPE error for type < 10 chars", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:a:bcd" // 9 chars
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE
        );
        expect(error?.message).toContain("at least 10 characters");
        expect(response).toBeNull();
      });

      it("should return INVALID_SUBJECT_TOKEN_TYPE error for type > 100 chars", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:" + "x".repeat(92) // 101 chars
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE
        );
        expect(error?.message).toContain("at most 100 characters");
        expect(response).toBeNull();
      });

      it("should return INVALID_SUBJECT_TOKEN_TYPE error for invalid URI format", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "not-a-valid-uri"
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE
        );
        expect(error?.message).toContain("valid URI");
        expect(response).toBeNull();
      });

      it("should accept valid URN with minimum length (10 chars)", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:a:bcde" // exactly 10 chars
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should accept valid URN with maximum length (100 chars)", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:" + "x".repeat(91) // exactly 100 chars
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should accept valid custom URN format", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token"
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should accept valid HTTPS URL format", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "https://example.com/token-type/v1"
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });
    });

    describe("actorToken validation", () => {
      it("should return MISSING_ACTOR_TOKEN_TYPE error when actorToken provided without actorTokenType", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorToken: "actor-token-value"
          // actorTokenType intentionally missing
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN_TYPE
        );
        expect(error?.message).toContain("actor_token_type is required");
        expect(response).toBeNull();
      });

      it("should ignore actorTokenType when actorToken is not provided", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorTokenType: "urn:acme:actor-type"
          // actorToken not provided - should be ignored, no error
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should accept actorToken when actorTokenType is also provided", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorToken: "actor-token-value",
          actorTokenType: "urn:acme:actor-type"
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should accept actorTokenType shorter than 10 chars (no length constraint for actor type)", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorToken: "actor-token-value",
          actorTokenType: "urn:a:bcd" // 9 chars — valid URN, no length restriction for actor_token_type
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });

      it("should return error when actorTokenType is not a valid URI", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorToken: "actor-token-value",
          actorTokenType: "not-a-valid-uri-1234"
        });

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.INVALID_ACTOR_TOKEN_TYPE
        );
        expect(error?.message).toContain("actor_token_type");
        expect(response).toBeNull();
      });

      it("should accept actorTokenType as HTTPS URL", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "valid-token",
          subjectTokenType: "urn:acme:legacy-token",
          actorToken: "actor-token-value",
          actorTokenType: "http://corporate-idp/id-token"
        });

        expect(error).toBeNull();
        expect(response).not.toBeNull();
      });
    });
  });

  describe("2: Successful Exchange Flows", () => {
    it("should successfully exchange token with minimal params", async () => {
      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token-123",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(response?.accessToken).toMatch(/^at_cte_test_/);
      expect(response?.refreshToken).toMatch(/^rt_cte_test_/);
      expect(response?.idToken).toBeDefined();
      expect(response?.tokenType.toLowerCase()).toBe("bearer");
      expect(response?.expiresIn).toBe(3600);
      expect(response?.scope).toContain("openid");
    });

    it("should merge user scope with default scopes", async () => {
      // Intercept request to verify scope merging
      let capturedScope = "";
      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            const body = await request.text();
            const params = new URLSearchParams(body);
            capturedScope = params.get("scope") || "";

            const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
              .setProtectedHeader({ alg: DEFAULT.alg })
              .setSubject(DEFAULT.sub)
              .setIssuedAt()
              .setIssuer(authorizationServerMetadata.issuer)
              .setAudience(DEFAULT.clientId)
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);

            return HttpResponse.json({
              token_type: "Bearer",
              access_token: "at_test",
              id_token: jwt,
              expires_in: 3600,
              scope: capturedScope
            });
          }
        )
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        scope: "read:data write:data"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      // Verify default scopes are merged
      expect(capturedScope).toContain("openid");
      expect(capturedScope).toContain("profile");
      expect(capturedScope).toContain("email");
      expect(capturedScope).toContain("offline_access");
      // Verify user scopes are included
      expect(capturedScope).toContain("read:data");
      expect(capturedScope).toContain("write:data");
    });

    it("should pass organization parameter to token endpoint", async () => {
      let capturedOrg = "";
      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            const body = await request.text();
            const params = new URLSearchParams(body);
            capturedOrg = params.get("organization") || "";

            const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
              .setProtectedHeader({ alg: DEFAULT.alg })
              .setSubject(DEFAULT.sub)
              .setIssuedAt()
              .setIssuer(authorizationServerMetadata.issuer)
              .setAudience(DEFAULT.clientId)
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);

            return HttpResponse.json({
              token_type: "Bearer",
              access_token: "at_test",
              id_token: jwt,
              expires_in: 3600
            });
          }
        )
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        organization: "org_abc123"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(capturedOrg).toBe("org_abc123");
    });

    it("should pass audience parameter to token endpoint", async () => {
      let capturedAudience = "";
      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            const body = await request.text();
            const params = new URLSearchParams(body);
            capturedAudience = params.get("audience") || "";

            const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
              .setProtectedHeader({ alg: DEFAULT.alg })
              .setSubject(DEFAULT.sub)
              .setIssuedAt()
              .setIssuer(authorizationServerMetadata.issuer)
              .setAudience(DEFAULT.clientId)
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);

            return HttpResponse.json({
              token_type: "Bearer",
              access_token: "at_test",
              id_token: jwt,
              expires_in: 3600
            });
          }
        )
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        audience: "https://api.example.com"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(capturedAudience).toBe("https://api.example.com");
    });

    it("should pass actor tokens to token endpoint", async () => {
      let capturedActorToken = "";
      let capturedActorTokenType = "";
      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            const body = await request.text();
            const params = new URLSearchParams(body);
            capturedActorToken = params.get("actor_token") || "";
            capturedActorTokenType = params.get("actor_token_type") || "";

            const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
              .setProtectedHeader({ alg: DEFAULT.alg })
              .setSubject(DEFAULT.sub)
              .setIssuedAt()
              .setIssuer(authorizationServerMetadata.issuer)
              .setAudience(DEFAULT.clientId)
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);

            return HttpResponse.json({
              token_type: "Bearer",
              access_token: "at_test",
              id_token: jwt,
              expires_in: 3600
            });
          }
        )
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        actorToken: "actor-jwt-token",
        actorTokenType: "urn:acme:actor-type"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(capturedActorToken).toBe("actor-jwt-token");
      expect(capturedActorTokenType).toBe("urn:acme:actor-type");
    });

    it("should pass additionalParameters to token endpoint", async () => {
      let capturedCustomParam = "";
      server.use(
        http.post(
          `https://${DEFAULT.domain}/oauth/token`,
          async ({ request }) => {
            const body = await request.text();
            const params = new URLSearchParams(body);
            capturedCustomParam = params.get("custom_claim") || "";

            const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
              .setProtectedHeader({ alg: DEFAULT.alg })
              .setSubject(DEFAULT.sub)
              .setIssuedAt()
              .setIssuer(authorizationServerMetadata.issuer)
              .setAudience(DEFAULT.clientId)
              .setExpirationTime("2h")
              .sign(keyPair.privateKey);

            return HttpResponse.json({
              token_type: "Bearer",
              access_token: "at_test",
              id_token: jwt,
              expires_in: 3600
            });
          }
        )
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        additionalParameters: {
          custom_claim: "custom-value-123"
        }
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(capturedCustomParam).toBe("custom-value-123");
    });

    it("should correctly map snake_case response to camelCase", async () => {
      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();

      // Verify all fields are properly mapped
      expect(response).toHaveProperty("accessToken");
      expect(response).toHaveProperty("refreshToken");
      expect(response).toHaveProperty("idToken");
      expect(response).toHaveProperty("tokenType");
      expect(response).toHaveProperty("expiresIn");
      expect(response).toHaveProperty("scope");

      // Verify no snake_case fields leaked through
      expect(response).not.toHaveProperty("access_token");
      expect(response).not.toHaveProperty("refresh_token");
      expect(response).not.toHaveProperty("id_token");
      expect(response).not.toHaveProperty("token_type");
      expect(response).not.toHaveProperty("expires_in");
    });

    it("should decode and return act claim from ID token", async () => {
      const actClaim = { sub: "agent|abc123", client_id: "agent-client" };
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            act: actClaim
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            token_type: "Bearer",
            access_token: "at_test",
            id_token: jwt,
            expires_in: 3600
          });
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        actorToken: "actor-jwt-token",
        actorTokenType: "urn:acme:actor-type"
      });

      expect(error).toBeNull();
      expect(response?.act).toEqual(actClaim);
    });

    it("should return undefined act when ID token has no act claim", async () => {
      // Default MSW handler issues an ID token without act claim
      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response?.act).toBeUndefined();
    });

    it("should return undefined act when no ID token in response", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json({
            token_type: "Bearer",
            access_token: "at_test",
            expires_in: 3600
            // no id_token
          });
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response?.act).toBeUndefined();
    });

    it("should preserve nested act delegation chain", async () => {
      const nestedAct = {
        sub: "service|xyz",
        act: { sub: "agent|abc123" }
      };
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            act: nestedAct
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            token_type: "Bearer",
            access_token: "at_test",
            id_token: jwt,
            expires_in: 3600
          });
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        actorToken: "actor-jwt-token",
        actorTokenType: "urn:acme:actor-type"
      });

      expect(error).toBeNull();
      expect(response?.act).toEqual(nestedAct);
      expect(response?.act?.act?.sub).toBe("agent|abc123");
    });

    it("should not error when refresh token is absent (actor token suppression)", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({ sid: DEFAULT.sid })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            token_type: "Bearer",
            access_token: "at_test",
            id_token: jwt,
            expires_in: 3600
            // no refresh_token — Auth0 suppresses it when actor_token is present
          });
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token",
        actorToken: "actor-jwt-token",
        actorTokenType: "urn:acme:actor-type"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(response?.refreshToken).toBeUndefined();
      expect(response?.accessToken).toBe("at_test");
    });
  });

  describe("3: DPoP Integration", () => {
    let dpopAuthClient: AuthClient;

    beforeEach(async () => {
      const dpopKeyPair = await generateDpopKeyPair();
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      dpopAuthClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        useDPoP: true,
        dpopKeyPair
      });
    });

    it("should use DPoP token type when DPoP is enabled", async () => {
      const [error, response] = await dpopAuthClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(response?.tokenType.toLowerCase()).toBe("dpop");
    });

    it("should handle DPoP nonce retry", async () => {
      // Enable nonce requirement
      dpopNonceState.requireNonce = true;

      const [error, response] = await dpopAuthClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeNull();
      expect(response).not.toBeNull();
      expect(response?.tokenType.toLowerCase()).toBe("dpop");
    });
  });

  describe("4: Error Handling", () => {
    it("should return EXCHANGE_FAILED error for invalid_grant response", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Token validation failed in Action"
            },
            { status: 400 }
          );
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "invalid-external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.EXCHANGE_FAILED);
      expect(error?.cause?.code).toBe("invalid_grant");
      expect(error?.cause?.message).toContain("Token validation failed");
      expect(response).toBeNull();
    });

    it("should return EXCHANGE_FAILED error for server_error response", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "server_error",
              error_description: "Internal error in Action"
            },
            { status: 500 }
          );
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.EXCHANGE_FAILED);
      // Note: 500 responses may not have error body parsed by oauth4webapi
      expect(error?.cause).toBeDefined();
      expect(response).toBeNull();
    });

    it("should return EXCHANGE_FAILED error for rate limit (429) response", async () => {
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "too_many_attempts",
              error_description: "Rate limit exceeded"
            },
            { status: 429 }
          );
        })
      );

      const [error, response] = await authClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.EXCHANGE_FAILED);
      expect(error?.cause?.code).toBe("too_many_attempts");
      expect(response).toBeNull();
    });

    it("should return EXCHANGE_FAILED error when discovery fails", async () => {
      // Override discovery to fail
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => {
            return HttpResponse.json(
              { error: "Discovery failed" },
              { status: 500 }
            );
          }
        )
      );

      // Need new client to trigger fresh discovery
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const freshClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes()
      });

      const [error, response] = await freshClient.customTokenExchange({
        subjectToken: "external-token",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.EXCHANGE_FAILED);
      expect(error?.message).toContain("discover");
      expect(response).toBeNull();
    });

    it("should be instance of CustomTokenExchangeError", async () => {
      const [error] = await authClient.customTokenExchange({
        subjectToken: "",
        subjectTokenType: "urn:acme:legacy-token"
      });

      expect(error).toBeInstanceOf(CustomTokenExchangeError);
      expect(error?.name).toBe("CustomTokenExchangeError");
    });
  });

  // -------------------------------------------------------------------------
  // 5: Session Transfer Token (STT) — requestSessionTransferToken
  // -------------------------------------------------------------------------

  describe("5: Session Transfer Token", () => {
    const STT_SUBJECT_TOKEN_TYPE = "urn:acme:subject-token";
    const STT_URN = TOKEN_TYPES.SESSION_TRANSFER_TOKEN;

    async function makeAgentIdToken(
      opts: { expiresIn?: string } = {}
    ): Promise<string> {
      return new jose.SignJWT({})
        .setProtectedHeader({ alg: DEFAULT.alg })
        .setSubject("agent|support-007")
        .setIssuedAt()
        .setIssuer(`https://${DEFAULT.domain}`)
        .setAudience(DEFAULT.clientId)
        .setExpirationTime(opts.expiresIn ?? "2h")
        .sign(keyPair.privateKey);
    }

    function makeAgentSession(
      idToken?: string,
      refreshToken?: string
    ): SessionData {
      return {
        user: { sub: "agent|support-007" },
        tokenSet: {
          accessToken: "at_agent",
          idToken,
          refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: "sid_agent",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
    }

    // STT token endpoint handler: returns an STT response shape
    function sttTokenHandler(
      opts: {
        error?: string;
        errorDescription?: string;
        status?: number;
      } = {}
    ) {
      return http.post(
        `https://${DEFAULT.domain}/oauth/token`,
        async ({ request }) => {
          if (opts.error) {
            return HttpResponse.json(
              {
                error: opts.error,
                error_description: opts.errorDescription ?? opts.error
              },
              { status: opts.status ?? 400 }
            );
          }

          const body = await request.text();
          const params = new URLSearchParams(body);

          // Capture params for inspection in tests via closure
          (sttTokenHandler as any)._lastParams = params;

          return HttpResponse.json({
            issued_token_type: STT_URN,
            access_token: "stt_opaque_" + params.get("subject_token"),
            token_type: "N_A",
            expires_in: 60,
            scope: params.get("scope") ?? "openid profile email"
          });
        }
      );
    }

    describe("5.1: result shape", () => {
      it("should return a SessionTransferTokenResult with issuedTokenType = SESSION_TRANSFER_TOKEN", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(sttTokenHandler());

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "my-subject",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).toBeNull();
        expect(result).not.toBeNull();
        expect(result?.issuedTokenType).toBe(STT_URN);
        expect(result?.sessionTransferToken).toContain("stt_opaque_");
        expect(result?.expiresIn).toBe(60);
        expect(result?.tokenType).toBe("N_A");
      });

      it("should expose sessionTransferToken, never access_token field", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(sttTokenHandler());

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "my-subject",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).toBeNull();
        expect(result).toHaveProperty("sessionTransferToken");
        expect(result).not.toHaveProperty("access_token");
        expect(result).not.toHaveProperty("accessToken");
      });

      it("should not include id_token or act on the result", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(sttTokenHandler());

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "my-subject",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).toBeNull();
        expect(result).not.toHaveProperty("act");
        expect(result).not.toHaveProperty("idToken");
      });
    });

    describe("5.2: actor resolution", () => {
      it("should use the session ID token as actor_token by default", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedActorToken = "";
        let capturedActorTokenType = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedActorToken = params.get("actor_token") ?? "";
              capturedActorTokenType = params.get("actor_token_type") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        const [error] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).toBeNull();
        expect(capturedActorToken).toBe(idToken);
        expect(capturedActorTokenType).toBe(TOKEN_TYPES.ID_TOKEN);
      });

      it("should use an explicit actor token when provided", async () => {
        const session = makeAgentSession(undefined); // no session ID token
        const explicitToken = await makeAgentIdToken();

        let capturedActorToken = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedActorToken = params.get("actor_token") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_explicit",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        const [error] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            actor: { token: explicitToken, type: TOKEN_TYPES.ID_TOKEN }
          },
          session
        );

        expect(error).toBeNull();
        expect(capturedActorToken).toBe(explicitToken);
      });

      it("should NOT attempt a session refresh when an explicit actor is blank, even if the session has a refresh token", async () => {
        const idToken = await makeAgentIdToken();
        // Session has a perfectly usable ID token and refresh token — irrelevant here,
        // since a blank explicit actor should fail on its own terms without touching them.
        const session = makeAgentSession(
          idToken,
          "rt_agent_should_not_be_used"
        );

        let refreshAttempted = false;
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              if (params.get("grant_type") === "refresh_token") {
                refreshAttempted = true;
              }
              return HttpResponse.json(
                { error: "unsupported_grant_type" },
                { status: 400 }
              );
            }
          )
        );

        const [error, result, refreshedSession] =
          await authClient.requestSessionTransferToken(
            {
              subjectToken: "sub-token",
              subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
              actor: { token: "  ", type: TOKEN_TYPES.ID_TOKEN }
            },
            session
          );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
        expect(refreshedSession).toBeNull();
        // A bad explicit actor is a caller input error the session can't fix —
        // refreshing the agent's own tokens must never be attempted for it.
        expect(refreshAttempted).toBe(false);
      });

      it("should return ACTOR_UNAVAILABLE when session has no ID token and no explicit actor", async () => {
        const session = makeAgentSession(undefined);

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).not.toBeNull();
        expect(error).toBeInstanceOf(CustomTokenExchangeError);
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
      });

      it("should return ACTOR_UNAVAILABLE when session is null", async () => {
        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          null
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
      });

      it("should return ACTOR_UNAVAILABLE when the session was created for a different MCD domain", async () => {
        // Defense-in-depth: Auth0Client.requestSessionTransferToken already enforces this via
        // getSession() -> getSessionWithDomainCheck, but AuthClient.requestSessionTransferToken
        // can be called directly, so it must not trust a session tagged for another domain.
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        session.internal.mcd = {
          domain: "brand-b.custom.example.com",
          issuer: `https://brand-b.custom.example.com/`
        };

        const [error, result, refreshedSession] =
          await authClient.requestSessionTransferToken(
            {
              subjectToken: "sub-token",
              subjectTokenType: STT_SUBJECT_TOKEN_TYPE
            },
            session
          );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
        expect(refreshedSession).toBeNull();
      });

      it("should allow an explicit actor even when the session is tagged for a different MCD domain", async () => {
        // An explicit actor bypasses the session entirely, so the cross-domain guard —
        // which only protects session-sourced actors — must not apply to it.
        const session = makeAgentSession(undefined);
        session.internal.mcd = {
          domain: "brand-b.custom.example.com",
          issuer: `https://brand-b.custom.example.com/`
        };
        const explicitToken = await makeAgentIdToken();

        server.use(
          http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
            return HttpResponse.json({
              issued_token_type: STT_URN,
              access_token: "stt_explicit_mcd",
              token_type: "N_A",
              expires_in: 60
            });
          })
        );

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            actor: { token: explicitToken, type: TOKEN_TYPES.ID_TOKEN }
          },
          session
        );

        expect(error).toBeNull();
        expect(result?.sessionTransferToken).toBe("stt_explicit_mcd");
      });

      it("should return ACTOR_UNAVAILABLE when session ID token is expired", async () => {
        const expiredToken = await new jose.SignJWT({})
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject("agent|expired")
          .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
          .setIssuer(`https://${DEFAULT.domain}`)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
          .sign(keyPair.privateKey);

        const session = makeAgentSession(expiredToken);
        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
      });

      it("should refresh the session ID token when expired and a refresh token is present, then use the refreshed token as actor", async () => {
        const expiredToken = await new jose.SignJWT({})
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject("agent|expired")
          .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
          .setIssuer(`https://${DEFAULT.domain}`)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
          .sign(keyPair.privateKey);

        const refreshedIdToken = await makeAgentIdToken();

        let capturedActorToken = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              const grantType = params.get("grant_type");

              if (grantType === "refresh_token") {
                return HttpResponse.json({
                  token_type: "Bearer",
                  access_token: "at_agent_refreshed",
                  refresh_token: "rt_agent_rotated",
                  id_token: refreshedIdToken,
                  expires_in: 3600,
                  scope: "openid profile email offline_access"
                });
              }

              // STT exchange — capture the actor_token used
              capturedActorToken = params.get("actor_token") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_refreshed_actor",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        const session = makeAgentSession(expiredToken, "rt_agent_original");
        const [error, result, refreshedSession] =
          await authClient.requestSessionTransferToken(
            {
              subjectToken: "sub-token",
              subjectTokenType: STT_SUBJECT_TOKEN_TYPE
            },
            session
          );

        expect(error).toBeNull();
        expect(result?.sessionTransferToken).toBe("stt_refreshed_actor");
        expect(capturedActorToken).toBe(refreshedIdToken);
        // The refreshed token set must be returned so the caller can persist it —
        // refresh token rotation invalidates the old refresh token in the session cookie.
        expect(refreshedSession?.tokenSet.refreshToken).toBe(
          "rt_agent_rotated"
        );
        expect(refreshedSession?.tokenSet.idToken).toBe(refreshedIdToken);
        // session.user must reflect the claims of the *new* ID token, not the expired one —
        // otherwise the persisted session would carry stale claims (e.g. old auth_time/sub).
        expect(refreshedSession?.user.sub).toBe("agent|support-007");
      });

      it("should surface MfaRequiredError when the refresh grant requires step-up, instead of collapsing to ACTOR_UNAVAILABLE", async () => {
        const expiredToken = await new jose.SignJWT({})
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject("agent|expired")
          .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
          .setIssuer(`https://${DEFAULT.domain}`)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
          .sign(keyPair.privateKey);

        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              if (params.get("grant_type") === "refresh_token") {
                return HttpResponse.json(
                  {
                    error: "mfa_required",
                    error_description:
                      "Multi-factor authentication is required.",
                    mfa_token: "mfa_tok_abc"
                  },
                  { status: 403 }
                );
              }
              return HttpResponse.json(
                { error: "unsupported_grant_type" },
                { status: 400 }
              );
            }
          )
        );

        const session = makeAgentSession(expiredToken, "rt_agent_original");
        const [error, result, refreshedSession] =
          await authClient.requestSessionTransferToken(
            {
              subjectToken: "sub-token",
              subjectTokenType: STT_SUBJECT_TOKEN_TYPE
            },
            session
          );

        expect(error).toBeInstanceOf(MfaRequiredError);
        // mfa_token is encrypted (with audience/scope context) before being handed back,
        // so it won't match the raw server value — just confirm one was produced.
        expect((error as MfaRequiredError).mfa_token).toBeTruthy();
        expect(result).toBeNull();
        expect(refreshedSession).toBeNull();
      });

      it("should return ACTOR_UNAVAILABLE when session ID token is expired and there is no refresh token", async () => {
        const expiredToken = await new jose.SignJWT({})
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject("agent|expired")
          .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
          .setIssuer(`https://${DEFAULT.domain}`)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
          .sign(keyPair.privateKey);

        const session = makeAgentSession(expiredToken); // no refreshToken
        const [error, result, refreshedSession] =
          await authClient.requestSessionTransferToken(
            {
              subjectToken: "sub-token",
              subjectTokenType: STT_SUBJECT_TOKEN_TYPE
            },
            session
          );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE
        );
        expect(result).toBeNull();
        expect(refreshedSession).toBeNull();
      });
    });

    describe("5.3: wire parameters", () => {
      it("should set audience to urn:{domain}:session_transfer", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedAudience = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedAudience = params.get("audience") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(capturedAudience).toBe(`urn:${DEFAULT.domain}:session_transfer`);
      });

      it("should set grant_type to token-exchange", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedGrantType = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedGrantType = params.get("grant_type") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(capturedGrantType).toBe(
          "urn:ietf:params:oauth:grant-type:token-exchange"
        );
      });

      it("should forward reason to the token endpoint", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedReason = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedReason = params.get("reason") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        const [error] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            reason: "Investigating TCK-4821"
          },
          session
        );

        expect(error).toBeNull();
        expect(capturedReason).toBe("Investigating TCK-4821");
      });

      it("should forward organization to the token endpoint", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedOrg = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedOrg = params.get("organization") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            organization: "org_globex"
          },
          session
        );

        expect(capturedOrg).toBe("org_globex");
      });

      it("should forward additionalParameters to the token endpoint", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedCustomParam = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedCustomParam = params.get("ticket_id") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            additionalParameters: { ticket_id: "TCK-4821" }
          },
          session
        );

        expect(capturedCustomParam).toBe("TCK-4821");
      });

      it("should NOT let additionalParameters override SDK-managed params", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedAudience = "";
        let capturedActorToken = "";
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedAudience = params.get("audience") ?? "";
              capturedActorToken = params.get("actor_token") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            additionalParameters: {
              audience: "urn:evil:override",
              actor_token: "spoofed-actor"
            }
          },
          session
        );

        // Managed params win — the injected overrides are ignored.
        expect(capturedAudience).toBe(`urn:${DEFAULT.domain}:session_transfer`);
        expect(capturedActorToken).toBe(idToken);
      });

      it("should NOT duplicate organization or reason when also passed via additionalParameters", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedParams: URLSearchParams | undefined;
        server.use(
          http.post(
            `https://${DEFAULT.domain}/oauth/token`,
            async ({ request }) => {
              capturedParams = new URLSearchParams(await request.text());
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE,
            organization: "org_legit",
            reason: "legit reason",
            additionalParameters: {
              organization: "org_injected",
              reason: "injected reason"
            }
          },
          session
        );

        // Each managed param must appear exactly once, with the SDK-set value —
        // additionalParameters must not be able to append a second, conflicting copy.
        expect(capturedParams?.getAll("organization")).toEqual(["org_legit"]);
        expect(capturedParams?.getAll("reason")).toEqual(["legit reason"]);
      });

      // MCD: the audience must be built from the domain the request is served on,
      // not a fixed configured domain, so the STT is issued for the right domain.
      it("should build the audience from the effective request domain (MCD)", async () => {
        const otherDomain = "brand-b.custom.example.com";
        const transactionStore = new TransactionStore({ secret });
        const sessionStore = new StatelessSessionStore({ secret });
        const mcdClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: otherDomain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes()
        });

        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        let capturedAudience = "";
        server.use(
          http.get(
            `https://${otherDomain}/.well-known/openid-configuration`,
            () =>
              HttpResponse.json({
                issuer: `https://${otherDomain}`,
                authorization_endpoint: `https://${otherDomain}/authorize`,
                token_endpoint: `https://${otherDomain}/oauth/token`,
                jwks_uri: `https://${otherDomain}/.well-known/jwks.json`,
                response_types_supported: ["code"],
                subject_types_supported: ["public"],
                id_token_signing_alg_values_supported: ["RS256"]
              })
          ),
          http.post(
            `https://${otherDomain}/oauth/token`,
            async ({ request }) => {
              const params = new URLSearchParams(await request.text());
              capturedAudience = params.get("audience") ?? "";
              return HttpResponse.json({
                issued_token_type: STT_URN,
                access_token: "stt_abc",
                token_type: "N_A",
                expires_in: 60
              });
            }
          )
        );

        await mcdClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(capturedAudience).toBe(`urn:${otherDomain}:session_transfer`);
      });
    });

    describe("5.4: STT never persisted / no act on response", () => {
      it("should not include the STT in any session-like field on the result", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(sttTokenHandler());

        const [, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        // Result must only have the documented fields
        const allowedKeys = new Set([
          "sessionTransferToken",
          "issuedTokenType",
          "expiresIn",
          "tokenType"
        ]);
        for (const key of Object.keys(result ?? {})) {
          expect(allowedKeys.has(key)).toBe(true);
        }
      });
    });

    describe("5.5: server error mapping", () => {
      it("should return SETACTOR_REQUIRED when server returns setactor_required", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(
          sttTokenHandler({
            error: "setactor_required",
            errorDescription:
              "setActor is required when requesting a session transfer token via token exchange.",
            status: 400
          })
        );

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.SETACTOR_REQUIRED
        );
        expect(result).toBeNull();
      });

      it("should return SESSION_TRANSFER_DISABLED when feature flag is off", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(
          sttTokenHandler({
            error: "session_transfer_disabled",
            errorDescription:
              "Session Transfer Tokens cannot be requested on this tenant.",
            status: 400
          })
        );

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED
        );
        expect(result).toBeNull();
      });

      it("should return EXCHANGE_FAILED for generic server errors", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);
        server.use(
          sttTokenHandler({
            error: "server_error",
            errorDescription: "Internal server error",
            status: 500
          })
        );

        const [error, result] = await authClient.requestSessionTransferToken(
          {
            subjectToken: "sub-token",
            subjectTokenType: STT_SUBJECT_TOKEN_TYPE
          },
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(CustomTokenExchangeErrorCode.EXCHANGE_FAILED);
        expect(result).toBeNull();
      });
    });

    describe("5.6: input validation", () => {
      it("should return MISSING_SUBJECT_TOKEN when subjectToken is empty", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        const [error, result] = await authClient.requestSessionTransferToken(
          { subjectToken: "", subjectTokenType: STT_SUBJECT_TOKEN_TYPE },
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN
        );
        expect(result).toBeNull();
      });

      it("should return INVALID_SUBJECT_TOKEN_TYPE for a short subjectTokenType", async () => {
        const idToken = await makeAgentIdToken();
        const session = makeAgentSession(idToken);

        const [error, result] = await authClient.requestSessionTransferToken(
          { subjectToken: "valid", subjectTokenType: "urn:a:b" }, // < 10 chars
          session
        );

        expect(error).not.toBeNull();
        expect(error?.code).toBe(
          CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE
        );
        expect(result).toBeNull();
      });
    });

    describe("5.7: buildSessionTransferRedirect", () => {
      it("should build a redirect URL with session_transfer_token param", () => {
        const result = {
          sessionTransferToken: "stt_abc123",
          issuedTokenType: STT_URN,
          expiresIn: 60
        };

        const redirect = authClient.buildSessionTransferRedirect(
          "https://app.example.com/auth/login",
          result
        );

        expect(redirect.status).toBeGreaterThanOrEqual(300);
        expect(redirect.status).toBeLessThan(400);
        const location = redirect.headers.get("location") ?? "";
        const url = new URL(location);
        expect(url.searchParams.get("session_transfer_token")).toBe(
          "stt_abc123"
        );
        expect(url.origin).toBe("https://app.example.com");
        expect(url.pathname).toBe("/auth/login");
      });

      it("should URL-encode the STT value", () => {
        const result = {
          sessionTransferToken: "stt_with+special=chars&more",
          issuedTokenType: STT_URN,
          expiresIn: 60
        };

        const redirect = authClient.buildSessionTransferRedirect(
          "https://app.example.com/auth/login",
          result
        );

        const location = redirect.headers.get("location") ?? "";
        const url = new URL(location);
        // searchParams.get() decodes it — should round-trip cleanly
        expect(url.searchParams.get("session_transfer_token")).toBe(
          "stt_with+special=chars&more"
        );
      });

      it("should append organization when provided via opts", () => {
        const result = {
          sessionTransferToken: "stt_org_flow",
          issuedTokenType: STT_URN,
          expiresIn: 60
        };

        const redirect = authClient.buildSessionTransferRedirect(
          "https://app.example.com/auth/login",
          result,
          { organization: "org_globex" }
        );

        const location = redirect.headers.get("location") ?? "";
        const url = new URL(location);
        expect(url.searchParams.get("organization")).toBe("org_globex");
        expect(url.searchParams.get("session_transfer_token")).toBe(
          "stt_org_flow"
        );
      });

      it("should not append organization when not provided", () => {
        const result = {
          sessionTransferToken: "stt_no_org",
          issuedTokenType: STT_URN,
          expiresIn: 60
        };

        const redirect = authClient.buildSessionTransferRedirect(
          "https://app.example.com/auth/login",
          result
        );

        const location = redirect.headers.get("location") ?? "";
        const url = new URL(location);
        expect(url.searchParams.has("organization")).toBe(false);
      });
    });

    describe("5.8: backward compatibility — existing CTE tests unaffected", () => {
      it("customTokenExchange should still work after adding STT methods", async () => {
        const [error, response] = await authClient.customTokenExchange({
          subjectToken: "legacy-token",
          subjectTokenType: "urn:acme:legacy-token"
        });

        expect(error).toBeNull();
        expect(response?.accessToken).toMatch(/^at_cte_test_/);
        expect(response?.tokenType.toLowerCase()).toBe("bearer");
      });

      it("customTokenExchange response should not have sessionTransferToken field", async () => {
        const [, response] = await authClient.customTokenExchange({
          subjectToken: "legacy-token",
          subjectTokenType: "urn:acme:legacy-token"
        });

        expect(response).not.toHaveProperty("sessionTransferToken");
        expect(response).not.toHaveProperty("issuedTokenType");
      });
    });

    // Pin the claim that handleLogin forwards all query params to /authorize
    // untouched, so session_transfer_token reaches the authorization endpoint
    // automatically on the target app side — no middleware change needed.
    describe("5.9: handleLogin forwards session_transfer_token to /authorize", () => {
      it("should forward session_transfer_token query param to the authorization URL", async () => {
        let capturedAuthorizeUrl = "";
        server.use(
          http.get(`https://${DEFAULT.domain}/authorize`, ({ request }) => {
            capturedAuthorizeUrl = request.url;
            return HttpResponse.text("", { status: 302 });
          })
        );

        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        loginUrl.searchParams.set("session_transfer_token", "stt_opaque_abc");
        const request = new NextRequest(loginUrl);

        const response = await authClient.handleLogin(request);

        // handleLogin redirects to /authorize; the location header holds the URL
        const authorizeUrl = new URL(
          response.headers.get("location") ?? capturedAuthorizeUrl
        );
        expect(authorizeUrl.searchParams.get("session_transfer_token")).toBe(
          "stt_opaque_abc"
        );
      });
    });
  });
});
