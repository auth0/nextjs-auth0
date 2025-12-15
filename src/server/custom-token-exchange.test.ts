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
  CustomTokenExchangeErrorCode
} from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
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
});
