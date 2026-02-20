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

import { AccessTokenErrorCode } from "../errors/index.js";
import { SessionData } from "../types/index.js";
import { Auth0Client } from "./client.js";

// Basic constants for testing
const domain = "https://auth0.local";
const alg = "RS256";
const sub = "test-sub";
const sid = "test-sid";
const scope = "openid profile email offline_access";

const testAuth0ClientConfig = {
  domain,
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.org",
  secret: "test-secret-long-enough-for-hs256-test-secret-long-enough-for-hs256"
};

let keyPair: jose.GenerateKeyPairResult;

const refreshedAccessToken = "msw-refreshed-access-token";
const refreshedRefreshToken = "msw-refreshed-refresh-token";
const refreshedExpiresIn = 3600;
const issuer = domain;
const audience = testAuth0ClientConfig.clientId;
const initialName = "initialName";
const updatedName = "updatedName";

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
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);

const handlers = [
  // OIDC Discovery Endpoint
  http.get(`${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: issuer,
      token_endpoint: `${domain}/oauth/token`,
      jwks_uri: `${domain}/.well-known/jwks.json`
    });
  }),
  // JWKS Endpoint
  http.get(`${domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  }),
  // Token Endpoint (for refresh token grant)
  http.post(
    `${domain}/oauth/token`,
    async ({ request }: { request: Request }) => {
      const body = await request.formData();

      if (
        body.get("grant_type") === "refresh_token" &&
        body.get("refresh_token")
      ) {
        return HttpResponse.json({
          access_token: refreshedAccessToken,
          refresh_token: refreshedRefreshToken,
          id_token: await generateToken({
            name: updatedName
          }),
          token_type: "Bearer",
          expires_in: refreshedExpiresIn,
          scope
        });
      }

      // Fallback for unexpected grant types or errors
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
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/**
 * Creates initial session data for tests.
 */
async function createInitialSession(): Promise<SessionData> {
  return {
    user: { sub, name: initialName },
    tokenSet: {
      accessToken: "test-access-token",
      refreshToken: "test-refresh-token",
      idToken: await generateToken({
        name: initialName
      }),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) + 3600 // Expires in 1 hour
    },
    internal: { sid, createdAt: Date.now() / 1000 }
  };
}

describe("Auth0Client - getAccessToken", () => {
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let mockGetSession: ReturnType<typeof vi.spyOn>;
  let auth0Client: Auth0Client;

  beforeEach(async () => {
    // Instantiate Auth0Client normally, it will use intercepted fetch
    auth0Client = new Auth0Client(testAuth0ClientConfig);

    // Mock saveToSession to avoid cookie/request context issues
    mockSaveToSession = vi
      .spyOn(Auth0Client.prototype as any, "saveToSession")
      .mockResolvedValue(undefined); // Mock successful save

    const initialSession = await createInitialSession();

    // Mock getSession specifically for this test
    mockGetSession = vi
      .spyOn(Auth0Client.prototype as any, "getSession")
      .mockResolvedValue(initialSession);
  });

  afterEach(() => {
    vi.restoreAllMocks(); // Restore mocks after each test
  });

  /**
   * Test Case: Pages Router Overload - getAccessToken(req, res, options)
   * Verifies that when called with req/res objects and refresh: true (with a valid token),
   * it refreshes the token.
   */
  it("should refresh token and save session for pages-router overload when refresh is true (with valid token)", async () => {
    // Pages router overload requires req/res objects
    const mockReq = new NextRequest(
      `https://${testAuth0ClientConfig.appBaseUrl}/api/test`
    );
    const mockRes = new NextResponse();

    // --- Execution ---
    const result = await auth0Client.getAccessToken(mockReq, mockRes, {
      refresh: true
    });

    // --- Assertions ---
    expect(result).not.toBeNull();
    expect(result?.token).toBe(refreshedAccessToken); // From msw handler

    // Check if expiresAt is close to the expected value based on the mock server response.
    // We use toBeCloseTo to account for minor timing differences between the client
    // calculating the expiration and the test assertion running.
    const expectedExpiresAtRough =
      Math.floor(Date.now() / 1000) + refreshedExpiresIn;
    // The '0' precision checks for equality at the integer second level.
    expect(result?.expiresAt).toBeCloseTo(expectedExpiresAtRough, 0);
    expect(mockSaveToSession).toHaveBeenCalledOnce();

    // Verify user profile data is updated in saved session
    const savedSessionData = mockSaveToSession.mock.calls[0][0] as SessionData;
    expect(savedSessionData.user.name).toBe(updatedName);
  });

  /**
   * Test Case: App Router Overload - getAccessToken(options)
   * Verifies that when called without req/res objects and refresh: true (with a valid token),
   * it refreshes the token.
   */
  it("should refresh token for app-router overload when refresh is true (with valid token)", async () => {
    // --- Execution ---
    const result = await auth0Client.getAccessToken({
      refresh: true
    });

    // --- Assertions ---
    expect(result).not.toBeNull();
    expect(result?.token).toBe(refreshedAccessToken);

    const expectedExpiresAtRough =
      Math.floor(Date.now() / 1000) + refreshedExpiresIn;

    expect(result?.expiresAt).toBeCloseTo(expectedExpiresAtRough, 0);
    expect(mockSaveToSession).toHaveBeenCalledOnce();

    // Verify user profile data is updated in saved session
    const savedSessionData = mockSaveToSession.mock.calls[0][0] as SessionData;
    expect(savedSessionData.user.name).toBe(updatedName);
  });

  it("should refresh token early when expiresAt is within tokenRefreshBuffer", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-01-01T00:00:00.000Z");
    vi.setSystemTime(now);

    try {
      auth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        tokenRefreshBuffer: 60
      });

      const session = await createInitialSession();
      session.tokenSet.expiresAt = Math.floor(now.getTime() / 1000) + 30;
      mockGetSession.mockResolvedValue(session);
      mockSaveToSession.mockClear();

      const result = await auth0Client.getAccessToken();

      expect(result).not.toBeNull();
      expect(result?.token).toBe(refreshedAccessToken);
      expect(mockSaveToSession).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it("should not refresh when expiresAt is outside tokenRefreshBuffer", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-01-01T00:00:00.000Z");
    vi.setSystemTime(now);

    try {
      auth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        tokenRefreshBuffer: 60
      });

      const session = await createInitialSession();
      session.tokenSet.expiresAt = Math.floor(now.getTime() / 1000) + 120;
      mockGetSession.mockResolvedValue(session);
      mockSaveToSession.mockClear();

      const result = await auth0Client.getAccessToken();

      expect(result).not.toBeNull();
      expect(result?.token).toBe("test-access-token");
      expect(mockSaveToSession).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("should not treat near-expiry as expired when no refresh token is available", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-01-01T00:00:00.000Z");
    vi.setSystemTime(now);

    try {
      auth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        tokenRefreshBuffer: 60
      });

      const session = await createInitialSession();
      session.tokenSet.expiresAt = Math.floor(now.getTime() / 1000) + 30;
      delete session.tokenSet.refreshToken;
      mockGetSession.mockResolvedValue(session);
      mockSaveToSession.mockClear();

      const result = await auth0Client.getAccessToken();

      expect(result).not.toBeNull();
      expect(result?.token).toBe("test-access-token");
      expect(mockSaveToSession).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("should still throw when token is expired and no refresh token is available", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-01-01T00:00:00.000Z");
    vi.setSystemTime(now);

    try {
      auth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        tokenRefreshBuffer: 60
      });

      const session = await createInitialSession();
      session.tokenSet.expiresAt = Math.floor(now.getTime() / 1000) - 10;
      delete session.tokenSet.refreshToken;
      mockGetSession.mockResolvedValue(session);

      await expect(auth0Client.getAccessToken()).rejects.toMatchObject({
        code: AccessTokenErrorCode.MISSING_REFRESH_TOKEN
      });
    } finally {
      vi.useRealTimers();
    }
  });
});
