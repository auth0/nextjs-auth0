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
  MockInstance,
  vi
} from "vitest";

import { SessionData } from "../types/index.js";
import { DEFAULT_SCOPES } from "../utils/constants.js";
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

const refreshedRefreshToken = "msw-refreshed-refresh-token";
const issuer = domain;
const audience = testAuth0ClientConfig.clientId;

/**
 * Helper to extract all access tokens from saved sessions
 */
function getAllSavedAccessTokens(mock: MockInstance): any[] {
  const allAccessTokens: any[] = [];
  for (const call of mock.mock.calls) {
    const session = call[0] as SessionData;
    if (session.accessTokens) {
      allAccessTokens.push(...session.accessTokens);
    }
  }
  return allAccessTokens;
}

/**
 * Helper to create a JWT access token for testing
 */
async function createTestToken(
  audience: string,
  scope?: string,
  claims?: any
): Promise<string> {
  return await new jose.SignJWT({
    ...(scope && { scope }),
    ...(claims && { ...claims })
  })
    .setProtectedHeader({ alg })
    .setSubject(sub)
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);
}

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
  // Setup MSW handler for multiple audiences
  http.post(`${domain}/oauth/token`, async ({ request }) => {
    const body = await request.formData();
    const requestedAudience = body.get("audience") as string;
    const requestedScope = body.get("scope") as string;

    const audiences = ["https://api1.example.com", "https://api2.example.com"];

    if (audiences.includes(requestedAudience)) {
      return HttpResponse.json({
        access_token: await createTestToken(requestedAudience, requestedScope),
        refresh_token: refreshedRefreshToken,
        id_token: await createTestToken(testAuth0ClientConfig.clientId),
        token_type: "Bearer",
        expires_in: 3600,
        scope: requestedScope
      });
    }

    return HttpResponse.json({ error: "invalid_request" }, { status: 400 });
  })
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
    user: { sub },
    tokenSet: {
      accessToken: "test-access-token",
      refreshToken: "test-refresh-token",
      idToken: await createTestToken(testAuth0ClientConfig.clientId),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) + 3600 // Expires in 1 hour
    },
    internal: { sid, createdAt: Date.now() / 1000 }
  };
}

describe("Auth0Client - getAccessToken (MRRT)", () => {
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
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
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );
  });

  afterEach(() => {
    vi.restoreAllMocks(); // Restore mocks after each test
  });

  /**
   * This verifies the main scenario of using MRRT with multiple audiences when called sequentially.
   * It ensures that when getAccessToken is called with different audiences,
   * separate access tokens are obtained and stored in the session correctly.
   */
  it("should handle multiple different audiences correctly when called sequentially", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 1
    const result1 = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope1
    });
    // Get token for audience 2
    const result2 = await auth0Client.getAccessToken({
      audience: audience2,
      scope: scope2
    });

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session seperatly
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessToken1 = allAccessTokens.find((t) => t.audience === audience1);
    const accessToken2 = allAccessTokens.find((t) => t.audience === audience2);

    expect(accessToken1).toBeDefined();
    expect(accessToken1!.accessToken).toBe(token1);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope1}`);

    expect(accessToken2).toBeDefined();
    expect(accessToken2!.accessToken).toBe(token2);
    expect(accessToken2!.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);
  });

  /**
   * This verifies the main scenario of using MRRT with multiple audiences when called in-parallel.
   * It ensures that when getAccessToken is called with different audiences,
   * separate access tokens are obtained and stored in the session correctly.
   */
  it("should handle multiple different audiences correctly when called in-parallel", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 1 and audience 2 in parallel
    const [result1, result2] = await Promise.all([
      auth0Client.getAccessToken({ audience: audience1, scope: scope1 }),
      auth0Client.getAccessToken({ audience: audience2, scope: scope2 })
    ]);

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session seperatly
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessToken1 = allAccessTokens.find((t) => t.audience === audience1);
    const accessToken2 = allAccessTokens.find((t) => t.audience === audience2);

    expect(accessToken1).toBeDefined();
    expect(accessToken1!.accessToken).toBe(token1);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope1}`);

    expect(accessToken2).toBeDefined();
    expect(accessToken2!.accessToken).toBe(token2);
    expect(accessToken2!.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);
  });

  /**
   * This verifies that when access tokens for different audiences already exist in the session,
   * they are reused correctly without making unnecessary token refresh calls.
   */
  it("should correctly call from the store when using different audiences", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const existingAcessToken1 = await createTestToken(audience1, scope1);

    const existingAcessToken2 = await createTestToken(audience, scope2);

    const session = {
      user: { sub },
      tokenSet: {
        accessToken: "expired-access-token",
        refreshToken: "test-refresh-token",
        idToken: await createTestToken(testAuth0ClientConfig.clientId),
        expiresAt: Math.floor(Date.now() / 1000) - 100 // Expired
      },
      accessTokens: [
        {
          audience: audience1,
          scope: `${DEFAULT_SCOPES} ${scope1}`,
          requestedScope: `${DEFAULT_SCOPES} ${scope1}`,
          accessToken: existingAcessToken1,
          // Not expired
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        {
          audience: audience2,
          scope: `${DEFAULT_SCOPES} ${scope2}`,
          requestedScope: `${DEFAULT_SCOPES} ${scope2}`,
          accessToken: existingAcessToken2,
          // Not expired
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        }
      ],
      internal: { sid, createdAt: Date.now() / 1000 }
    };

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 1
    const result1 = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope1
    });
    // Get token for audience 2
    const result2 = await auth0Client.getAccessToken({
      audience: audience2,
      scope: scope2
    });

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    expect(mockSaveToSession).not.toHaveBeenCalled();

    expect(token1).toBe(existingAcessToken1);
    expect(token2).toBe(existingAcessToken2);
  });

  /**
   * This verifies that when an access token for a specific audience is expired,
   * it is refreshed correctly using the MRRT, while other valid access tokens remain unchanged.
   */
  it("should correctly refresh when expired", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const existingAcessToken1 = await createTestToken(audience1, scope1);

    const existingAcessToken2 = await createTestToken(audience, scope2);

    const session = {
      user: { sub },
      tokenSet: {
        accessToken: "expired-access-token",
        refreshToken: "test-refresh-token",
        idToken: await createTestToken(testAuth0ClientConfig.clientId),
        expiresAt: Math.floor(Date.now() / 1000) - 100 // Expired
      },
      accessTokens: [
        {
          audience: audience1,
          scope: `${DEFAULT_SCOPES} ${scope1}`,
          requestedScope: `${DEFAULT_SCOPES} ${scope1}`,
          accessToken: existingAcessToken1,
          // Not expired
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        {
          audience: audience2,
          scope: `${DEFAULT_SCOPES} ${scope2}`,
          requestedScope: `${DEFAULT_SCOPES} ${scope2}`,
          accessToken: existingAcessToken2,
          // Expired!
          expiresAt: Math.floor(Date.now() / 1000) - 100
        }
      ],
      internal: { sid, createdAt: Date.now() / 1000 }
    };

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 1
    const result1 = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope1
    });
    // Get token for audience 2
    const result2 = await auth0Client.getAccessToken({
      audience: audience2,
      scope: scope2
    });

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    // As the token for audience2 was expired, we expect a save to session as it was refreshed
    expect(mockSaveToSession).toHaveBeenCalled();

    // Expect the first token to be unchanged, as it was not expired
    expect(token1).toBe(existingAcessToken1);
    // Expect the second token to be new, as it was expired and had to be refreshed
    expect(token2).toBeDefined();
    expect(token2).not.toBe(existingAcessToken2);

    // Verify the session contains the updated access token for audience2, but the same for audience1
    const savedSession = mockSaveToSession.mock.calls[0][0] as SessionData;

    expect(savedSession.accessTokens).toBeDefined();
    expect(savedSession.accessTokens).toHaveLength(2);

    const sessionAccessTokenForAudience1 = savedSession.accessTokens?.find(
      (t) => t.audience === audience1
    );
    const sessionAccessTokenForAudience2 = savedSession.accessTokens?.find(
      (t) => t.audience === audience2
    );

    expect(sessionAccessTokenForAudience1).toBeDefined();
    expect(sessionAccessTokenForAudience1!.accessToken).toBe(
      existingAcessToken1
    );

    expect(sessionAccessTokenForAudience2).toBeDefined();
    expect(sessionAccessTokenForAudience2!.accessToken).toBe(token2);
  });
});
