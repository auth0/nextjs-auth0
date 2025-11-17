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
    const audiences = [
      "https://api.example.com",
      "https://api1.example.com",
      "https://api2.example.com"
    ];

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

/**
 * Helper to extract all access tokens from saved sessions calls
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

describe("Auth0Client - getAccessToken (Concurrent Calls)", () => {
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

  it("should handle multiple concurrent calls with the same audience and scope correctly", async () => {
    const audience = "https://api.example.com";
    const apiScope = "read:messages write:messages";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Make 3 concurrent calls with the same audience and scope
    const [result1, result2, result3] = await Promise.all([
      auth0Client.getAccessToken({ audience, scope: apiScope }),
      auth0Client.getAccessToken({ audience, scope: apiScope }),
      auth0Client.getAccessToken({ audience, scope: apiScope })
    ]);

    // All should return the same token
    const token1 = result1.token;
    expect(result2.token).toBe(token1);
    expect(result3.token).toBe(token1);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify the session contains only a single entry for the access token
    const savedSession = mockSaveToSession.mock.calls[0][0] as SessionData;
    expect(savedSession.accessTokens).toBeDefined();
    expect(savedSession.accessTokens).toHaveLength(1);
    expect(savedSession.accessTokens![0].audience).toBe(audience);
    expect(savedSession.accessTokens![0].accessToken).toBe(token1);
  });

  it("should handle multiple concurrent calls with different audiences correctly", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Make concurrent calls with different audiences (1 call per audience)
    const [result1, result2] = await Promise.all([
      auth0Client.getAccessToken({ audience: audience1, scope: scope1 }),
      auth0Client.getAccessToken({ audience: audience2, scope: scope2 })
    ]);

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session
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

  it("should handle multiple concurrent calls with different audiences correctly when mixed with identical ones as well", async () => {
    const audience1 = "https://api1.example.com";
    const audience2 = "https://api2.example.com";
    const scope1 = "read:api1";
    const scope2 = "read:api2";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Make concurrent calls with different audiences (2 calls per audience)
    const [result1, result2, result3, result4] = await Promise.all([
      auth0Client.getAccessToken({ audience: audience1, scope: scope1 }),
      auth0Client.getAccessToken({ audience: audience2, scope: scope2 }),
      auth0Client.getAccessToken({ audience: audience1, scope: scope1 }),
      auth0Client.getAccessToken({ audience: audience2, scope: scope2 })
    ]);

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(result1.token).toBe(token1);
    expect(result3.token).toBe(token1);
    expect(result2.token).toBe(token2);
    expect(result4.token).toBe(token2);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessToken1 = allAccessTokens.find((t) => t.audience === audience1);
    const accessToken2 = allAccessTokens.find((t) => t.audience === audience2);

    // NOTE: Without request deduplication (cache removed), concurrent calls with
    // identical parameters will each execute independently. This means we may get
    // multiple tokens saved for the same audience/scope combination, though they
    // should have the same value. The test now verifies that all tokens are present.
    expect(allAccessTokens.length).toBeGreaterThanOrEqual(2);

    expect(accessToken1).toBeDefined();
    expect(accessToken1!.accessToken).toBe(token1);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope1}`);

    expect(accessToken2).toBeDefined();
    expect(accessToken2!.accessToken).toBe(token2);
    expect(accessToken2!.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);
  });

  it("should handle concurrent calls with the same audience but different scopes", async () => {
    const audience = "https://api.example.com";
    const scope1 = "read:messages";
    const scope2 = "read:messages write:messages";

    const session = await createInitialSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Make concurrent calls with same audience but different scopes
    const [result1, result2] = await Promise.all([
      auth0Client.getAccessToken({ audience, scope: scope1 }),
      auth0Client.getAccessToken({ audience, scope: scope2 })
    ]);

    // Both should return valid tokens
    expect(result1.token).toBeDefined();
    expect(result1.scope).toBeDefined();
    expect(result2.token).toBeDefined();
    expect(result2.scope).toBeDefined();

    // Both tokens are different
    expect(result1.token).not.toEqual(result2.token);

    // Verify at least one valid scope was returned
    // (Due to caching, results may vary, but both should be valid)
    expect(result1.scope).toBe(`${DEFAULT_SCOPES} ${scope1}`);
    expect(result2.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);

    // Verify session was saved with access tokens for the audience
    expect(mockSaveToSession).toHaveBeenCalled();
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const audienceTokens = allAccessTokens.filter(
      (t) => t.audience === audience
    );
    expect(audienceTokens.length).toBeGreaterThanOrEqual(1);
  });
});
