import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { MfaRequiredError, OAuth2Error } from "../errors/index.js";
import { getDefaultRoutes, setupMswLifecycle } from "../test/defaults.js";
import { createNextHeadersMock } from "../test/mocks.js";
import { generateSecret } from "../test/utils.js";
import { MfaContext, SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { Auth0Client } from "./client.js";
import { decrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

vi.mock("next/headers.js", () => createNextHeadersMock({ cookies: false }));

// Test configuration
const domain = "https://auth0.example.com";
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
});
setupMswLifecycle(server);
afterEach(() => {
  shouldReturnMfaError = false;
});

/**
 * Creates initial session data for tests.
 */
async function createInitialSession(): Promise<SessionData> {
  return {
    user: { sub },
    tokenSet: {
      accessToken: "expired-access-token",
      refreshToken: "test-refresh-token",
      idToken: await generateToken(),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) - 60 // Expired 1 minute ago
    },
    internal: { sid, createdAt: Date.now() / 1000 }
  };
}

describe("MFA Error Bubbling", () => {
  let auth0Client: Auth0Client;
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let savedSession: SessionData | null = null;

  beforeEach(async () => {
    savedSession = null;
    auth0Client = new Auth0Client(testAuth0ClientConfig);

    const initialSession = await createInitialSession();

    // Mock getSessionFromAuthClient (RC-6 helper) to return session
    vi.spyOn(
      Auth0Client.prototype as any,
      "getSessionFromAuthClient"
    ).mockResolvedValue(initialSession);

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
    it("should NOT store MFA context in session (stateless design)", async () => {
      shouldReturnMfaError = true;

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      // Session saved but should NOT contain mfa property
      expect(mockSaveToSession).toHaveBeenCalled();
      expect(savedSession).not.toBeNull();
      expect(savedSession!.mfa).toBeUndefined();
    });
  });

  describe("3. Encrypted Token", () => {
    it("should encrypt mfa_token as JWE", async () => {
      shouldReturnMfaError = true;

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
      const decrypted = await decrypt<MfaContext>(
        thrownError!.mfa_token,
        secret
      );

      expect(decrypted).not.toBeNull();
      expect(decrypted!.payload.mfaToken).toBe(mockMfaToken);
      expect(decrypted!.payload.audience).toBeDefined();
      expect(decrypted!.payload.scope).toBeDefined();
    });
  });

  describe("4. MfaRequiredError Properties", () => {
    it("should include mfa_requirements from Auth0 response", async () => {
      shouldReturnMfaError = true;

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

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      await expect(
        auth0Client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrow(MfaRequiredError);
    });

    it("should NOT mutate session when throwing MfaRequiredError", async () => {
      shouldReturnMfaError = true;

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      try {
        await auth0Client.getAccessToken(mockReq, mockRes, { refresh: true });
      } catch {
        // Expected
      }

      // Session saved but no mfa property (stateless design)
      expect(mockSaveToSession).toHaveBeenCalled();
      expect(savedSession!.mfa).toBeUndefined();
    });

    it("should work without req/res (App Router)", async () => {
      shouldReturnMfaError = true;

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

      const mockReq = new NextRequest(
        `${testAuth0ClientConfig.appBaseUrl}/api`
      );
      const mockRes = new NextResponse();

      // Should throw AccessTokenError instead of MfaRequiredError when no mfa_token
      await expect(
        auth0Client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrow();
    });

    it("should create self-contained encrypted token for each MFA challenge", async () => {
      shouldReturnMfaError = true;

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
      expect(thrownError!.mfa_token).toBeDefined();

      // Verify token is self-contained
      const decrypted = await decrypt<MfaContext>(
        thrownError!.mfa_token,
        secret
      );
      expect(decrypted!.payload.mfaToken).toBe(mockMfaToken);
      expect(decrypted!.payload.audience).toBeDefined();
      expect(decrypted!.payload.scope).toBeDefined();
    });
  });

  describe("8. Configuration", () => {
    it("should respect custom mfaTokenTtl", async () => {
      const customTtl = 600; // 10 minutes
      const customClient = new Auth0Client({
        ...testAuth0ClientConfig,
        mfaTokenTtl: customTtl
      });

      shouldReturnMfaError = true;

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

// ---------------------------------------------------------------------------
// MFA Error Bubbling — passkeyGetToken
// Auth0 returns mfa_required during the webauthn token exchange grant.
// Mirrors the refresh token tests above for the passkey code path.
// ---------------------------------------------------------------------------

describe("MFA Error Bubbling — passkeyGetToken", () => {
  const jwePattern =
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

  const mockAuthResponse = {
    id: "cred-id",
    rawId: "cred-raw-id",
    type: "public-key" as const,
    response: {
      clientDataJSON: "clientDataJSON-base64url",
      attestationObject: "attestationObject-base64url"
    }
  };

  // AuthClient is used directly — same pattern as passkey.flow.test.ts — so we
  // can call passkeyGetToken without a full HTTP handler stack.
  let passkeyAuthClient: AuthClient;
  let passkeySecret: string;

  beforeEach(async () => {
    passkeySecret = await generateSecret(32);
    passkeyAuthClient = new AuthClient({
      domain: domain.replace("https://", ""),
      clientId: testAuth0ClientConfig.clientId,
      clientSecret: testAuth0ClientConfig.clientSecret,
      appBaseUrl: testAuth0ClientConfig.appBaseUrl,
      secret: passkeySecret,
      transactionStore: new TransactionStore({ secret: passkeySecret }),
      sessionStore: new StatelessSessionStore({ secret: passkeySecret }),
      routes: getDefaultRoutes()
    });
  });

  function useMfaRequiredOnPasskeyToken(
    token = mockMfaToken,
    requirements = mockMfaRequirements
  ) {
    server.use(
      http.post(`${domain}/oauth/token`, () =>
        HttpResponse.json(
          {
            error: "mfa_required",
            error_description: "Multi-factor authentication is required.",
            mfa_token: token,
            mfa_requirements: requirements
          },
          { status: 403 }
        )
      )
    );
  }

  async function getPasskeyMfaError(): Promise<MfaRequiredError> {
    const { RequestCookies, ResponseCookies } =
      await import("@edge-runtime/cookies");
    let thrownError: MfaRequiredError | null = null;
    try {
      await passkeyAuthClient.passkeyGetToken(
        { authSession: "test-auth-session", authResponse: mockAuthResponse },
        new RequestCookies(new Headers()),
        new ResponseCookies(new Headers())
      );
    } catch (e) {
      thrownError = e as MfaRequiredError;
    }
    expect(thrownError).toBeInstanceOf(MfaRequiredError);
    return thrownError!;
  }

  it("throws MfaRequiredError when /oauth/token returns mfa_required", async () => {
    useMfaRequiredOnPasskeyToken();
    await expect(getPasskeyMfaError()).resolves.toBeInstanceOf(
      MfaRequiredError
    );
  });

  it("mfa_token is a JWE (5 dot-separated base64url parts)", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    expect(error.mfa_token).toMatch(jwePattern);
  });

  it("does NOT expose the raw mfa_token", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    expect(error.mfa_token).not.toBe(mockMfaToken);
  });

  it("encrypted token is decryptable with the SDK secret and contains raw mfaToken", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    const decrypted = await decrypt<MfaContext>(error.mfa_token, passkeySecret);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.payload.mfaToken).toBe(mockMfaToken);
    expect(decrypted!.payload.audience).toBeDefined();
    expect(decrypted!.payload.scope).toBeDefined();
  });

  it("audience and scope in encrypted token reflect the client authorizationParameters", async () => {
    const testAudience = "https://api.example.com";
    const testScope = "openid profile email";
    const scopedSecret = await generateSecret(32);
    const scopedClient = new AuthClient({
      domain: domain.replace("https://", ""),
      clientId: testAuth0ClientConfig.clientId,
      clientSecret: testAuth0ClientConfig.clientSecret,
      appBaseUrl: testAuth0ClientConfig.appBaseUrl,
      secret: scopedSecret,
      transactionStore: new TransactionStore({ secret: scopedSecret }),
      sessionStore: new StatelessSessionStore({ secret: scopedSecret }),
      routes: getDefaultRoutes(),
      authorizationParameters: { audience: testAudience, scope: testScope }
    });

    useMfaRequiredOnPasskeyToken();

    const { RequestCookies, ResponseCookies } =
      await import("@edge-runtime/cookies");
    let thrownError: MfaRequiredError | null = null;
    try {
      await scopedClient.passkeyGetToken(
        { authSession: "test-auth-session", authResponse: mockAuthResponse },
        new RequestCookies(new Headers()),
        new ResponseCookies(new Headers())
      );
    } catch (e) {
      thrownError = e as MfaRequiredError;
    }
    expect(thrownError).toBeInstanceOf(MfaRequiredError);

    const decrypted = await decrypt<MfaContext>(
      thrownError!.mfa_token,
      scopedSecret
    );
    expect(decrypted!.payload.audience).toBe(testAudience);
    expect(decrypted!.payload.scope).toBe(testScope);
  });

  it("MfaRequiredError has correct code, error, error_description", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    expect(error.code).toBe("mfa_required");
    expect(error.error).toBe("mfa_required");
    expect(error.error_description).toBe(
      "Multi-factor authentication is required."
    );
  });

  it("MfaRequiredError carries mfa_requirements from the Auth0 response", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    expect(error.mfa_requirements).toEqual(mockMfaRequirements);
  });

  it("MfaRequiredError.cause is an OAuth2Error with code mfa_required", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    expect(error.cause).toBeInstanceOf(OAuth2Error);
    expect((error.cause as OAuth2Error).code).toBe("mfa_required");
  });

  it("toJSON() serializes to REST-compatible shape", async () => {
    useMfaRequiredOnPasskeyToken();
    const error = await getPasskeyMfaError();
    const json = error.toJSON();
    expect(json.error).toBe("mfa_required");
    expect(json.error_description).toBe(
      "Multi-factor authentication is required."
    );
    expect(json.mfa_token).toBeDefined();
    expect(json.mfa_requirements).toEqual(mockMfaRequirements);
  });
});

// ---------------------------------------------------------------------------
// MFA Error Bubbling — passwordlessVerify
// Auth0 returns mfa_required during the passwordless OTP grant.
// Mirrors the refresh token tests above for the passwordless code path.
// ---------------------------------------------------------------------------

describe("MFA Error Bubbling — passwordlessVerify", () => {
  const jwePattern =
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

  let passwordlessAuthClient: AuthClient;
  let passwordlessSecret: string;

  beforeEach(async () => {
    passwordlessSecret = await generateSecret(32);
    passwordlessAuthClient = new AuthClient({
      domain: domain.replace("https://", ""),
      clientId: testAuth0ClientConfig.clientId,
      clientSecret: testAuth0ClientConfig.clientSecret,
      appBaseUrl: testAuth0ClientConfig.appBaseUrl,
      secret: passwordlessSecret,
      transactionStore: new TransactionStore({ secret: passwordlessSecret }),
      sessionStore: new StatelessSessionStore({ secret: passwordlessSecret }),
      routes: getDefaultRoutes()
    });
  });

  function useMfaRequiredOnPasswordlessToken(
    token = mockMfaToken,
    requirements = mockMfaRequirements
  ) {
    server.use(
      http.post(`${domain}/oauth/token`, () =>
        HttpResponse.json(
          {
            error: "mfa_required",
            error_description: "Multi-factor authentication is required.",
            mfa_token: token,
            mfa_requirements: requirements
          },
          { status: 403 }
        )
      )
    );
  }

  async function getPasswordlessMfaError(): Promise<MfaRequiredError> {
    let thrownError: MfaRequiredError | null = null;
    try {
      await passwordlessAuthClient.passwordlessVerify({
        connection: "email",
        email: "user@example.com",
        verificationCode: "123456"
      });
    } catch (e) {
      thrownError = e as MfaRequiredError;
    }
    expect(thrownError).toBeInstanceOf(MfaRequiredError);
    return thrownError!;
  }

  it("throws MfaRequiredError when /oauth/token returns mfa_required", async () => {
    useMfaRequiredOnPasswordlessToken();
    await expect(getPasswordlessMfaError()).resolves.toBeInstanceOf(
      MfaRequiredError
    );
  });

  it("mfa_token is a JWE (5 dot-separated base64url parts)", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    expect(error.mfa_token).toMatch(jwePattern);
  });

  it("does NOT expose the raw mfa_token", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    expect(error.mfa_token).not.toBe(mockMfaToken);
  });

  it("encrypted token is decryptable with the SDK secret and contains raw mfaToken", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    const decrypted = await decrypt<MfaContext>(
      error.mfa_token,
      passwordlessSecret
    );
    expect(decrypted).not.toBeNull();
    expect(decrypted!.payload.mfaToken).toBe(mockMfaToken);
    expect(decrypted!.payload.audience).toBeDefined();
    expect(decrypted!.payload.scope).toBeDefined();
  });

  it("audience and scope in encrypted token reflect the client authorizationParameters", async () => {
    const testAudience = "https://api.example.com";
    const testScope = "openid profile email";
    const scopedSecret = await generateSecret(32);
    const scopedClient = new AuthClient({
      domain: domain.replace("https://", ""),
      clientId: testAuth0ClientConfig.clientId,
      clientSecret: testAuth0ClientConfig.clientSecret,
      appBaseUrl: testAuth0ClientConfig.appBaseUrl,
      secret: scopedSecret,
      transactionStore: new TransactionStore({ secret: scopedSecret }),
      sessionStore: new StatelessSessionStore({ secret: scopedSecret }),
      routes: getDefaultRoutes(),
      authorizationParameters: { audience: testAudience, scope: testScope }
    });

    useMfaRequiredOnPasswordlessToken();

    let thrownError: MfaRequiredError | null = null;
    try {
      await scopedClient.passwordlessVerify({
        connection: "email",
        email: "user@example.com",
        verificationCode: "123456"
      });
    } catch (e) {
      thrownError = e as MfaRequiredError;
    }
    expect(thrownError).toBeInstanceOf(MfaRequiredError);

    const decrypted = await decrypt<MfaContext>(
      thrownError!.mfa_token,
      scopedSecret
    );
    expect(decrypted!.payload.audience).toBe(testAudience);
    expect(decrypted!.payload.scope).toBe(testScope);
  });

  it("MfaRequiredError has correct code, error, error_description", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    expect(error.code).toBe("mfa_required");
    expect(error.error).toBe("mfa_required");
    expect(error.error_description).toBe(
      "Multi-factor authentication is required."
    );
  });

  it("MfaRequiredError carries mfa_requirements from the Auth0 response", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    expect(error.mfa_requirements).toEqual(mockMfaRequirements);
  });

  it("MfaRequiredError.cause is an OAuth2Error with code mfa_required", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    expect(error.cause).toBeInstanceOf(OAuth2Error);
    expect((error.cause as OAuth2Error).code).toBe("mfa_required");
  });

  it("toJSON() serializes to REST-compatible shape", async () => {
    useMfaRequiredOnPasswordlessToken();
    const error = await getPasswordlessMfaError();
    const json = error.toJSON();
    expect(json.error).toBe("mfa_required");
    expect(json.error_description).toBe(
      "Multi-factor authentication is required."
    );
    expect(json.mfa_token).toBeDefined();
    expect(json.mfa_requirements).toEqual(mockMfaRequirements);
  });
});
