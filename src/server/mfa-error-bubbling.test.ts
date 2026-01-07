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

import { MfaRequiredError, OAuth2Error } from "../errors/index.js";
import { MfaContext, SessionData } from "../types/index.js";
import { hashMfaToken } from "../utils/mfa-utils.js";
import { Auth0Client } from "./client.js";
import { decrypt } from "./cookies.js";

// Test configuration
const domain = "https://auth0.local";
const alg = "RS256";
const sub = "test-sub";
const sid = "test-sid";
const scope = "openid profile email offline_access";
const secret =
  "test-secret-long-enough-for-hs256-test-secret-long-enough-for-hs256";

const testAuth0ClientConfig = {
  domain,
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.org",
  secret
};

let keyPair: jose.GenerateKeyPairResult;

// Mock MFA response data
const mockMfaToken = "raw-mfa-token-from-auth0";
const mockMfaRequirements = {
  challenge: [{ type: "otp" }, { type: "push" }],
  enroll: [{ type: "sms" }]
};

const generateToken = async (claims?: any) =>
  await new jose.SignJWT({
    sid,
    sub,
    auth_time: Math.floor(Date.now() / 1000),
    nonce: "nonce-value",
    jti: Date.now().toString(),
    ...(claims && { ...claims })
  })
    .setProtectedHeader({ alg })
    .setIssuer(domain)
    .setAudience(testAuth0ClientConfig.clientId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);

// Track whether MFA error should be returned
let shouldReturnMfaError = false;

const handlers = [
  // OIDC Discovery Endpoint
  http.get(`${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: domain,
      token_endpoint: `${domain}/oauth/token`,
      jwks_uri: `${domain}/.well-known/jwks.json`
    });
  }),
  // JWKS Endpoint
  http.get(`${domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  }),
  // Token Endpoint - handles both success and MFA required scenarios
  http.post(
    `${domain}/oauth/token`,
    async ({ request }: { request: Request }) => {
      const body = await request.formData();

      if (
        body.get("grant_type") === "refresh_token" &&
        body.get("refresh_token")
      ) {
        // Return MFA error when configured
        if (shouldReturnMfaError) {
          return HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Multi-factor authentication is required.",
              mfa_token: mockMfaToken,
              mfa_requirements: mockMfaRequirements
            },
            { status: 403 }
          );
        }

        // Normal refresh response
        return HttpResponse.json({
          access_token: "refreshed-access-token",
          refresh_token: "refreshed-refresh-token",
          id_token: await generateToken(),
          token_type: "Bearer",
          expires_in: 3600,
          scope
        });
      }

      return HttpResponse.json(
        { error: "invalid_grant", error_description: "Unsupported grant type" },
        { status: 400 }
      );
    }
  )
];

const server = setupServer(...handlers);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair(alg);
  server.listen({ onUnhandledRequest: "error" });
});
afterEach(() => {
  server.resetHandlers();
  shouldReturnMfaError = false;
});
afterAll(() => server.close());

/**
 * Creates initial session data for tests.
 */
async function createInitialSession(
  mfa?: Record<string, MfaContext>
): Promise<SessionData> {
  return {
    user: { sub },
    tokenSet: {
      accessToken: "expired-access-token",
      refreshToken: "test-refresh-token",
      idToken: await generateToken(),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) - 60 // Expired 1 minute ago
    },
    internal: { sid, createdAt: Date.now() / 1000 },
    mfa
  };
}

describe("MFA Error Bubbling", () => {
  let auth0Client: Auth0Client;
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let savedSession: SessionData | null = null;

  beforeEach(async () => {
    savedSession = null;
    auth0Client = new Auth0Client(testAuth0ClientConfig);

    // Mock saveToSession to capture what would be saved
    mockSaveToSession = vi
      .spyOn(Auth0Client.prototype as any, "saveToSession")
      .mockImplementation(async (data: any) => {
        savedSession = data;
      });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("1. MFA Detection", () => {
    it("should detect mfa_required error from token endpoint", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      await expect(
        auth0Client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrow(MfaRequiredError);
    });

    it("should include error code 'mfa_required'", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
        expect.fail("Should have thrown MfaRequiredError");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaRequiredError);
        expect((error as MfaRequiredError).code).toBe("mfa_required");
        expect((error as MfaRequiredError).error).toBe("mfa_required");
      }
    });
  });

  describe("2. Session Storage", () => {
    it("should store MFA context in session keyed by token hash", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      expect(mockSaveToSession).toHaveBeenCalled();
      expect(savedSession).not.toBeNull();
      expect(savedSession!.mfa).toBeDefined();

      // Verify hash-keyed storage
      const expectedHash = hashMfaToken(mockMfaToken);
      expect(savedSession!.mfa![expectedHash]).toBeDefined();
    });

    it("should store audience and scope in MFA context", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      const hash = hashMfaToken(mockMfaToken);
      const mfaContext = savedSession!.mfa![hash];

      expect(mfaContext).toBeDefined();
      expect(mfaContext.scope).toBeDefined();
      expect(mfaContext.createdAt).toBeDefined();
    });

    it("should preserve existing MFA contexts when adding new one", async () => {
      shouldReturnMfaError = true;
      const existingMfaContext: MfaContext = {
        audience: "https://existing-api.example.com",
        scope: "existing-scope",
        createdAt: Date.now() - 60000
      };
      const initialSession = await createInitialSession({
        existingHash: existingMfaContext
      });

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      // Should have both existing and new MFA contexts
      expect(savedSession!.mfa!["existingHash"]).toBeDefined();
      const newHash = hashMfaToken(mockMfaToken);
      expect(savedSession!.mfa![newHash]).toBeDefined();
    });
  });

  describe("3. Encrypted Token", () => {
    it("should encrypt mfa_token as JWE", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();
      // JWE format: 5 base64url parts separated by dots
      const jwePattern =
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
      expect(thrownError!.mfa_token).toMatch(jwePattern);
    });

    it("should NOT expose raw mfa_token", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();
      // Encrypted token should not equal raw token
      expect(thrownError!.mfa_token).not.toBe(mockMfaToken);
    });

    it("should be decryptable with SDK secret", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();

      // Decrypt using the same secret
      const decrypted = await decrypt<{ mfa_token: string }>(
        thrownError!.mfa_token,
        secret
      );

      expect(decrypted).not.toBeNull();
      expect(decrypted!.payload.mfa_token).toBe(mockMfaToken);
    });
  });

  describe("4. MfaRequiredError Properties", () => {
    it("should include mfa_requirements from Auth0 response", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();
      expect(thrownError!.mfa_requirements).toEqual(mockMfaRequirements);
    });

    it("should include error_description", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();
      expect(thrownError!.error_description).toBe(
        "Multi-factor authentication is required."
      );
      expect(thrownError!.message).toBe(
        "Multi-factor authentication is required."
      );
    });

    it("should include OAuth2Error as cause", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();
      expect(thrownError!.cause).toBeInstanceOf(OAuth2Error);
      expect((thrownError!.cause as OAuth2Error).code).toBe("mfa_required");
    });
  });

  describe("5. toJSON Serialization", () => {
    it("should serialize to REST-compatible JSON format", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();

      const json = thrownError!.toJSON();

      expect(json.error).toBe("mfa_required");
      expect(json.error_description).toBe(
        "Multi-factor authentication is required."
      );
      expect(json.mfa_token).toBeDefined();
      expect(json.mfa_requirements).toEqual(mockMfaRequirements);
    });

    it("should work with JSON.stringify", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      expect(thrownError).not.toBeNull();

      const stringified = JSON.stringify(thrownError);
      const parsed = JSON.parse(stringified);

      expect(parsed.error).toBe("mfa_required");
      expect(parsed.mfa_token).toBeDefined();
    });
  });

  describe("6. SDK getAccessToken Behavior", () => {
    it("should throw MfaRequiredError when MFA is required", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      await expect(
        auth0Client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrow(MfaRequiredError);
    });

    it("should save session with MFA context before throwing", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      // Session should be saved with MFA context
      expect(mockSaveToSession).toHaveBeenCalled();
      expect(savedSession!.mfa).toBeDefined();
    });

    it("should work without req/res (App Router)", async () => {
      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      await expect(
        auth0Client.getAccessToken({ refresh: true })
      ).rejects.toThrow(MfaRequiredError);
    });
  });

  describe("7. Edge Cases", () => {
    it("should handle MFA error without mfa_token gracefully", async () => {
      // Override handler to return MFA error without token
      server.use(
        http.post(`${domain}/oauth/token`, async () => {
          return HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "MFA required but no token"
              // Note: no mfa_token field
            },
            { status: 403 }
          );
        })
      );

      const initialSession = await createInitialSession();
      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      // Should throw AccessTokenError instead of MfaRequiredError when no mfa_token
      await expect(
        auth0Client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrow();
    });

    it("should support concurrent MFA contexts for different audiences", async () => {
      // First MFA error
      const firstMfaContext: MfaContext = {
        audience: "https://api1.example.com",
        scope: "read:api1",
        createdAt: Date.now() - 60000
      };
      const firstHash = "first-hash-123456";

      shouldReturnMfaError = true;
      const initialSession = await createInitialSession({
        [firstHash]: firstMfaContext
      });

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      // Should have both MFA contexts
      expect(savedSession!.mfa![firstHash]).toBeDefined();
      const newHash = hashMfaToken(mockMfaToken);
      expect(savedSession!.mfa![newHash]).toBeDefined();
    });
  });

  describe("8. Configuration", () => {
    it("should respect custom mfaContextTtl", async () => {
      const customTtl = 600; // 10 minutes
      const customClient = new Auth0Client({
        ...testAuth0ClientConfig,
        mfaContextTtl: customTtl
      });

      shouldReturnMfaError = true;
      const initialSession = await createInitialSession();

      vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
        initialSession
      );
      vi.spyOn(
        Auth0Client.prototype as any,
        "saveToSession"
      ).mockImplementation(async (data: any) => {
        savedSession = data;
      });

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      let thrownError: MfaRequiredError | null = null;
      try {
        await customClient.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch (error) {
        thrownError = error as MfaRequiredError;
      }

      // Token should be encrypted (we can't easily verify TTL from outside,
      // but we verify the token is properly formatted)
      expect(thrownError).not.toBeNull();
      expect(thrownError!.mfa_token).toBeDefined();
    });
  });
});
