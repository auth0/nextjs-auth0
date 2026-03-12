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
const issuer = domain;
const audience = testAuth0ClientConfig.clientId;

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

// MSW handlers — discovery + JWKS only, token endpoint overridden per test
const baseHandlers = [
  http.get(`${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: issuer,
      token_endpoint: `${domain}/oauth/token`,
      jwks_uri: `${domain}/.well-known/jwks.json`
    });
  }),
  http.get(`${domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  })
];

const server = setupServer(...baseHandlers);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair(alg);
  server.listen({ onUnhandledRequest: "error" });
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

async function createExpiredSession(): Promise<SessionData> {
  return {
    user: { sub, name: "Test User" },
    tokenSet: {
      accessToken: "expired-access-token",
      refreshToken: "test-refresh-token",
      idToken: await generateToken(),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
    },
    internal: { sid, createdAt: Date.now() / 1000 }
  };
}

describe("5xx Error Details Flow", () => {
  let auth0Client: Auth0Client;

  beforeEach(async () => {
    auth0Client = new Auth0Client(testAuth0ClientConfig);

    vi.spyOn(Auth0Client.prototype as any, "saveToSession").mockResolvedValue(
      undefined
    );

    const session = await createExpiredSession();
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      session
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should preserve error details from 5xx token endpoint response during refresh", async () => {
    // Mock token endpoint to return 500 with structured error body
    server.use(
      http.post(`${domain}/oauth/token`, () => {
        return HttpResponse.json(
          {
            error: "access_denied",
            error_description: "Denied by Action"
          },
          { status: 500 }
        );
      })
    );

    try {
      await auth0Client.getAccessToken({ refresh: true });
      expect.fail("Should have thrown AccessTokenError");
    } catch (e: any) {
      expect(e.code).toBe(AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN);
      expect(e.cause).toBeDefined();
      expect(e.cause.code).toBe("access_denied");
      expect(e.cause.message).toBe("Denied by Action");
    }
  });

  it("should fall back to unknown_error when 5xx response body is not JSON", async () => {
    // Mock token endpoint to return 500 with non-JSON body
    server.use(
      http.post(`${domain}/oauth/token`, () => {
        return HttpResponse.text("Internal Server Error", { status: 500 });
      })
    );

    try {
      await auth0Client.getAccessToken({ refresh: true });
      expect.fail("Should have thrown AccessTokenError");
    } catch (e: any) {
      expect(e.code).toBe(AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN);
      expect(e.cause).toBeDefined();
      expect(e.cause.code).toBe("unknown_error");
    }
  });
});
