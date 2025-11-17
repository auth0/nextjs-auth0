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

import { SessionData } from "../types/index.js";
import { Auth0Client } from "./client.js";
import { Fetcher } from "./fetcher.js";

const domain = "https://auth0.local";
const issuer = domain;
const alg = "RS256";
const sub = "test-sub";
const sid = "test-sid";
const scope = "openid profile email offline_access";

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

let keyPair: jose.GenerateKeyPairResult;
const refreshedRefreshToken = "msw-refreshed-refresh-token";
const testAuth0ClientConfig = {
  domain,
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.org",
  secret: "test-secret-long-enough-for-hs256-test-secret-long-enough-for-hs256"
};

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
      "https://api-dpop.example.com"
    ];

    if (audiences.includes(requestedAudience)) {
      return HttpResponse.json({
        access_token: await createTestToken(requestedAudience, requestedScope),
        refresh_token: refreshedRefreshToken,
        id_token: await createTestToken(testAuth0ClientConfig.clientId),
        token_type:
          requestedAudience === "https://api-dpop.example.com"
            ? "DPoP"
            : "Bearer",
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

describe("Fetcher", () => {
  let mockFetch: any;

  beforeEach(async () => {
    mockFetch = vi.fn().mockResolvedValue(new Response("OK"));

    // Mock saveToSession to avoid cookie/request context issues
    // We do not need this here, we can rely purely on what we get from oauth/token.
    vi.spyOn(Auth0Client.prototype as any, "saveToSession").mockResolvedValue(
      undefined
    );

    const initialSession = await createInitialSession();

    // Mock getSession specifically for this test
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("DPoP functionality", () => {
    let fetcher: Fetcher<Response>;

    beforeEach(async () => {
      const dpopAuthClient = new Auth0Client({
        ...testAuth0ClientConfig,
        useDPoP: true,
        dpopKeyPair: keyPair
      });

      fetcher = await dpopAuthClient.createFetcher(undefined, {
        fetch: mockFetch
      });
    });
    it("should use DPoP when enabled", async () => {
      await fetcher.fetchWithAuth("https://api.example.com/data", {
        audience: "https://api-dpop.example.com",
        scope: "read:data"
      });

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers["authorization"]).toMatch(/^DPoP /);
      expect(headers["DPoP"]).not.toBeNull();
    });

    it("should not use DPoP when enabled but token is not bound", async () => {
      await fetcher.fetchWithAuth("https://api.example.com/data", {
        audience: "https://api.example.com",
        scope: "read:data"
      });

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers["authorization"]).toMatch(/^Bearer /);
      expect(headers["DPoP"]).toBeUndefined();
    });

    it("should be able to mix dpop and bearer", async () => {
      await fetcher.fetchWithAuth("https://api.example.com/data", {
        audience: "https://api.example.com",
        scope: "read:data"
      });

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers["authorization"]).toMatch(/^Bearer /);
      expect(headers["DPoP"]).toBeUndefined();

      await fetcher.fetchWithAuth("https://api.example.com/data", {
        audience: "https://api-dpop.example.com",
        scope: "read:data"
      });

      const headers2 = mockFetch.mock.calls[1][1].headers;
      expect(headers2["authorization"]).toMatch(/^DPoP /);
      expect(headers2["DPoP"]).not.toBeDefined();
    });
  });
});
