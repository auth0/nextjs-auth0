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

import { SessionData, TokenSet } from "../types/index.js";
import { Auth0Client } from "./client.js";

// Basic constants for testing
const DEFAULT = {
  domain: "https://op.example.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.org",
  secret: "test-secret-long-enough-for-hs256-test-secret-long-enough-for-hs256",
  alg: "RS256",
  sub: "test-sub",
  sid: "test-sid",
  scope: "openid profile email offline_access"
};

const initialTokenSetBase = {
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token",
  idToken: "test-id-token",
  scope: DEFAULT.scope
};

const authClientConfig = {
  domain: DEFAULT.domain,
  clientId: DEFAULT.clientId,
  clientSecret: DEFAULT.clientSecret,
  appBaseUrl: DEFAULT.appBaseUrl,
  secret: DEFAULT.secret
};

// msw server setup
let keyPair: jose.GenerateKeyPairResult;
const refreshedAccessToken = "msw-refreshed-access-token";
const refreshedRefreshToken = "msw-refreshed-refresh-token";
const refreshedExpiresIn = 3600;
const issuer = DEFAULT.domain;
const audience = DEFAULT.clientId;

const handlers = [
  // OIDC Discovery Endpoint
  http.get(`${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: issuer,
      token_endpoint: `${DEFAULT.domain}/oauth/token`,
      jwks_uri: `${DEFAULT.domain}/.well-known/jwks.json`
    });
  }),
  // JWKS Endpoint
  http.get(`${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  }),
  // Token Endpoint (for refresh token grant)
  http.post(
    `${DEFAULT.domain}/oauth/token`,
    async ({ request }: { request: Request }) => {
      const body = await request.formData();

      if (
        body.get("grant_type") === "refresh_token" &&
        body.get("refresh_token")
      ) {
        // Generate a new ID token for the refreshed set
        const newIdToken = await new jose.SignJWT({
          sid: DEFAULT.sid,
          sub: DEFAULT.sub,
          auth_time: Math.floor(Date.now() / 1000),
          nonce: "nonce-value" // Example nonce
        })
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setIssuer(issuer)
          .setAudience(audience)
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(keyPair.privateKey);

        return HttpResponse.json({
          access_token: refreshedAccessToken,
          refresh_token: refreshedRefreshToken,
          id_token: newIdToken,
          token_type: "Bearer",
          expires_in: refreshedExpiresIn,
          scope: DEFAULT.scope // Assuming scope doesn't change on refresh
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
  keyPair = await jose.generateKeyPair(DEFAULT.alg);
  server.listen({ onUnhandledRequest: "error" });
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/**
 * Creates initial session data for tests.
 */
function createInitialSession(): SessionData {
  // Use a VALID (non-expired) initial token
  const initialExpiresAt = Math.floor(Date.now() / 1000) + 3600; // Expires in 1 hour
  const initialTokenSet: TokenSet = {
    ...initialTokenSetBase, // Spread the base token set from the new constant
    expiresAt: initialExpiresAt // Add the dynamic expiration time
  };
  const initialSession: SessionData = {
    user: { sub: DEFAULT.sub },
    tokenSet: initialTokenSet,
    internal: { sid: DEFAULT.sid, createdAt: Date.now() / 1000 }
  };
  return initialSession;
}

describe("Auth0Client - getAccessToken", () => {
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let auth0Client: Auth0Client;

  beforeEach(async () => {
    // Instantiate Auth0Client normally, it will use intercepted fetch
    auth0Client = new Auth0Client(authClientConfig);

    // Mock saveToSession to avoid cookie/request context issues
    mockSaveToSession = vi
      .spyOn(Auth0Client.prototype as any, "saveToSession")
      .mockResolvedValue(undefined); // Mock successful save
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
    const initialSession = createInitialSession();

    // Mock getSession specifically for this test
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );

    // Pages router overload requires req/res objects
    const mockReq = new NextRequest(`https://${DEFAULT.appBaseUrl}/api/test`);
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
  });

  /**
   * Test Case: App Router Overload - getAccessToken(options)
   * Verifies that when called without req/res objects and refresh: true (with a valid token),
   * it refreshes the token.
   */
  it("should refresh token for app-router overload when refresh is true (with valid token)", async () => {
    const initialSession = createInitialSession();

    // Mock getSession specifically for this test
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );

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
  });
});
