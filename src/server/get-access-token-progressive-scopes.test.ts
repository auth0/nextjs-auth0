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

describe("Auth0Client - getAccessToken (without progressiveScopes)", () => {
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

  it("should result in seperate tokens for the same audience", async () => {
    const audience1 = "https://api1.example.com";
    const scope1 = "read:api1";
    const scope2 = "write:api1";

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
      audience: audience1,
      scope: scope2
    });

    // Verify tokens for each audience
    const token1 = result1.token;
    const token2 = result2.token;
    expect(token1).not.toBe(token2);

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session seperatly
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessTokens = allAccessTokens.filter((t) => t.audience === audience1);
    const accessToken1 = accessTokens[0];
    const accessToken2 = accessTokens[1];

    expect(accessToken1).toBeDefined();
    expect(accessToken1!.accessToken).toBe(token1);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope1}`);

    expect(accessToken2).toBeDefined();
    expect(accessToken2!.accessToken).toBe(token2);
    expect(accessToken2!.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);
  });
});

describe("Auth0Client - getAccessToken (with progressiveScopes)", () => {
  let mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let auth0Client: Auth0Client;

  beforeEach(async () => {
    // Instantiate Auth0Client normally, it will use intercepted fetch
    auth0Client = new Auth0Client({
      ...testAuth0ClientConfig,
      progressiveScopes: true
    });

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


  it("should result in a single token for the same audience and progressively increase scope", async () => {
    const audience1 = "https://api1.example.com";
    const scope1 = "read:api1";
    const scope2 = "write:api1";

    const session = await createInitialSession();

    session.accessTokens = [{
      accessToken: 'existing-access-token',
      audience: 'https://api1.example.com',
      scope: 'openid profile email offline_access read:api1',
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    }];

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 2
    const result = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope2
    });

    // Verify tokens for each audience
    const token = result.token;

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session seperatly
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessTokens = allAccessTokens.filter((t) => t.audience === audience1);
    const accessToken1 = accessTokens[0];
    const accessToken2 = accessTokens[1];

    expect(accessToken1).toBeDefined();
    expect(accessToken2).not.toBeDefined();
    expect(accessToken1!.accessToken).toBe(token);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope1} ${scope2}`);
  });

  it("should correctly read from the cache if already available with requestedScope", async () => {
    const audience1 = "https://api1.example.com";
    const scope2 = "write:api1";

    const session = await createInitialSession();

    session.accessTokens = [{
      accessToken: 'existing-access-token',
      audience: 'https://api1.example.com',
      scope: 'openid profile email offline_access read:api1 write:api1',
      requestedScope: 'openid profile email offline_access read:api1 write:api1',
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    }];

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 2
    const result = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope2
    });

    // Verify tokens for each audience
    const token = result.token;

    expect(mockSaveToSession).not.toHaveBeenCalled()
    expect(token).toBeDefined();
  });

  it("should correctly read from the cache if already available without requestedScope", async () => {
    const audience1 = "https://api1.example.com";
    const scope2 = "write:api1";

    const session = await createInitialSession();

    session.accessTokens = [{
      accessToken: 'existing-access-token',
      audience: 'https://api1.example.com',
      scope: 'openid profile email offline_access read:api1 write:api1',
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    }];

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 2
    const result = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope2
    });

    // Verify tokens for each audience
    const token = result.token;

    expect(mockSaveToSession).not.toHaveBeenCalled()
    expect(token).toBeDefined();
  });

   it("should progressively reduce scopes based on lastRequestedAt", async () => {
    const audience1 = "https://api1.example.com";
    const scope2 = "write:api1";

    const session = await createInitialSession();

    session.accessTokens = [{
      accessToken: 'existing-access-token',
      audience: 'https://api1.example.com',
      scope: 'openid profile email offline_access read:api1',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scopeMetadata: {
        'read:api1': { lastRequestedAt: Date.now() - 10000 }
      }
    }];

    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );

    // Get token for audience 2
    const result = await auth0Client.getAccessToken({
      audience: audience1,
      scope: scope2
    });

    // Verify tokens for each audience
    const token = result.token;

    expect(mockSaveToSession).toHaveBeenCalled();

    // Verify both audiences are stored in session seperatly
    const allAccessTokens = getAllSavedAccessTokens(mockSaveToSession);
    const accessTokens = allAccessTokens.filter((t) => t.audience === audience1);
    const accessToken1 = accessTokens[0];
    const accessToken2 = accessTokens[1];

    expect(accessToken1).toBeDefined();
    expect(accessToken2).not.toBeDefined();
    expect(accessToken1!.accessToken).toBe(token);
    expect(accessToken1!.scope).toBe(`${DEFAULT_SCOPES} ${scope2}`);
  });
});
