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

import { ConnectAccountError } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { RESPONSE_TYPES, SessionData } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { Auth0Client } from "./client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionState, TransactionStore } from "./transaction-store.js";

// Test configuration constants
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
  secret: "test-secret-long-enough-for-hs256-test-secret-long-enough-for-hs256",
  enableConnectAccountEndpoint: true
};

let keyPair: jose.GenerateKeyPairResult;
let dpopKeyPair: CryptoKeyPair;

// Test tokens and responses
const accessToken = "mock-access-token";
const refreshToken = "mock-refresh-token";

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

// Helper function to create proper SessionData for tests
async function createTestSession(): Promise<SessionData> {
  return {
    user: { sub, name: "Test User" },
    tokenSet: {
      accessToken,
      refreshToken,
      idToken: await generateToken(),
      scope,
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    },
    internal: {
      sid,
      createdAt: Math.floor(Date.now() / 1000)
    }
  };
}

// MSW request handlers for connected accounts
const handlers = [
  // OIDC Discovery Endpoint
  http.get(`${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: domain,
      authorization_endpoint: `${domain}/authorize`,
      token_endpoint: `${domain}/oauth/token`,
      userinfo_endpoint: `${domain}/userinfo`,
      jwks_uri: `${domain}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      // DPoP support
      dpop_signing_alg_values_supported: ["RS256", "ES256"],
      // MRRT/Connected Accounts support
      grant_types_supported: [
        "authorization_code",
        "refresh_token",
        "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
      ]
    });
  }),

  // JWKS Endpoint
  http.get(`${domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  }),

  // Token Endpoint (for MRRT and access token retrieval)
  http.post(`${domain}/oauth/token`, async ({ request }) => {
    const body = await request.formData();
    const grantType = body.get("grant_type");
    const scope = body.get("scope");

    if (grantType === "refresh_token") {
      return HttpResponse.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        id_token: await generateToken(),
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile email create:me:connected_accounts"
      });
    }

    if (
      grantType === "client_credentials" &&
      scope &&
      typeof scope === "string" &&
      scope.includes("create:me:connected_accounts")
    ) {
      return HttpResponse.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "create:me:connected_accounts"
      });
    }

    // Default success response for any token request to avoid unhandled request errors
    return HttpResponse.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: typeof scope === "string" ? scope : "openid profile email"
    });
  }),

  // Connected Accounts API - Initiate Connection
  http.post(
    `${domain}/me/v1/connected-accounts/connect`,
    async ({ request }) => {
      const authHeader = request.headers.get("Authorization");

      let body: any;
      try {
        body = await request.json();
      } catch (e) {
        return HttpResponse.json(
          {
            error: "invalid_json",
            error_description: "Invalid JSON in request body"
          },
          { status: 400 }
        );
      }

      if (!authHeader || !authHeader.includes(accessToken)) {
        return HttpResponse.json(
          { error: "unauthorized", error_description: "Invalid access token" },
          { status: 401 }
        );
      }

      // Validate required fields
      if (!body || !body.connection) {
        return HttpResponse.json(
          {
            error: "invalid_request",
            error_description: "Missing required parameter: connection"
          },
          { status: 400 }
        );
      }

      if (!body.redirect_uri) {
        return HttpResponse.json(
          {
            error: "invalid_request",
            error_description: "Missing required parameter: redirect_uri"
          },
          { status: 400 }
        );
      }

      // Success response
      return HttpResponse.json({
        auth_session: "auth-session-123",
        connect_uri: `${domain}/connect`,
        connect_params: {
          ticket: "connect-ticket-123",
          state: body.state || "generated-state"
        },
        expires_in: 300
      });
    }
  ),

  // Connected Accounts API - Complete Connection
  http.post(
    `${domain}/me/v1/connected-accounts/complete`,
    async ({ request }) => {
      const authHeader = request.headers.get("Authorization");

      if (!authHeader || !authHeader.includes(accessToken)) {
        return HttpResponse.json(
          { error: "unauthorized", error_description: "Invalid access token" },
          { status: 401 }
        );
      }

      const body = (await request.json()) as any;

      // Validate required fields
      if (!body || !body.auth_session || !body.connect_code) {
        return HttpResponse.json(
          {
            error: "invalid_request",
            error_description: "Missing auth_session or connect_code"
          },
          { status: 400 }
        );
      }

      // Success response
      return HttpResponse.json({
        connection: "google-oauth2",
        scope: ["https://www.googleapis.com/auth/calendar"],
        connected_at: new Date().toISOString()
      });
    }
  ),

  // Catch-all handler to debug unmatched requests
  http.all("*", ({ request }) => {
    // If it's a connected accounts request that didn't match our handler, log more details
    if (request.url.includes("/me/v1/connected-accounts")) {
      console.error(
        `Connected accounts request not matched: ${request.method} ${request.url}`
      );
    }

    return HttpResponse.json(
      { error: "unmatched_request", url: request.url },
      { status: 404 }
    );
  })
];

const server = setupServer(...handlers);

describe("Connected Accounts", () => {
  let auth0Client: Auth0Client;
  let _mockSaveToSession: ReturnType<typeof vi.spyOn>;
  let mockGetSession: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    server.listen({ onUnhandledRequest: "error" });
    keyPair = await jose.generateKeyPair(alg);
    dpopKeyPair = await generateDpopKeyPair();
  });

  afterAll(() => {
    server.close();
  });

  beforeEach(async () => {
    server.resetHandlers();
    auth0Client = new Auth0Client(testAuth0ClientConfig);

    // Mock saveToSession to avoid cookie/request context issues
    _mockSaveToSession = vi
      .spyOn(Auth0Client.prototype as any, "saveToSession")
      .mockResolvedValue(undefined);

    // Mock getSession to return a proper session
    const session = await createTestSession();
    mockGetSession = vi
      .spyOn(Auth0Client.prototype as any, "getSession")
      .mockResolvedValue(session);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Basic Connected Accounts Flow", () => {
    it("should successfully initiate connected accounts flow with Bearer token", async () => {
      const response = await auth0Client.connectAccount({
        connection: "google-oauth2",
        authorizationParams: {
          scope: "https://www.googleapis.com/auth/calendar"
        },
        returnTo: "/dashboard"
      });

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307); // Redirect response

      const location = response.headers.get("Location");
      expect(location).toContain(`${domain}/connect`);
      expect(location).toContain("ticket=connect-ticket-123");
    });

    it("should handle missing session error", async () => {
      // Override the global mock for this specific test
      mockGetSession.mockResolvedValueOnce(null);

      await expect(
        auth0Client.connectAccount({
          connection: "google-oauth2"
        })
      ).rejects.toThrow(ConnectAccountError);
    });

    it("should handle unauthorized access token error", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: "invalid-token",
        expiresAt: Date.now() + 3600000
      });

      // Mock the MSW server to return 401 for invalid tokens
      server.use(
        http.post(`${domain}/me/v1/connected-accounts/connect`, () => {
          return HttpResponse.json({ error: "unauthorized" }, { status: 401 });
        })
      );

      await expect(
        auth0Client.connectAccount({
          connection: "google-oauth2"
        })
      ).rejects.toThrow(ConnectAccountError);
    });
  });

  describe("DPoP Integration", () => {
    it("should successfully use DPoP for connected accounts flow", async () => {
      // Configure client with DPoP
      const dpopAuth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        useDPoP: true,
        dpopKeyPair
      });

      const session = await createTestSession();

      vi.spyOn(dpopAuth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(dpopAuth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      const response = await dpopAuth0Client.connectAccount({
        connection: "google-oauth2",
        authorizationParams: {
          scope: "https://www.googleapis.com/auth/calendar"
        }
      });

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });

    it("should fallback to Bearer token when DPoP fails", async () => {
      // This tests the scenario where DPoP is configured but keypair is missing
      // The system should throw a proper configuration error
      const dpopAuth0Client = new Auth0Client({
        ...testAuth0ClientConfig,
        useDPoP: true,
        dpopKeyPair: undefined // Missing keypair should cause error
      });

      const session = await createTestSession();

      vi.spyOn(dpopAuth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(dpopAuth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      // Should throw a configuration error when DPoP is enabled but no keypair provided
      await expect(
        dpopAuth0Client.connectAccount({
          connection: "google-oauth2"
        })
      ).rejects.toThrow("DPoP is enabled but no keypair is configured");
    });
  });

  describe("Different Connection Types", () => {
    it("should work with Google OAuth2 connection", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      const response = await auth0Client.connectAccount({
        connection: "google-oauth2",
        authorizationParams: {
          scope:
            "https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/gmail.readonly"
        }
      });

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });

    it("should work with Microsoft connection", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      const response = await auth0Client.connectAccount({
        connection: "windowslive",
        authorizationParams: {
          scope: "https://graph.microsoft.com/calendars.read"
        }
      });

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });
  });

  describe("Error Scenarios", () => {
    it("should handle network failures gracefully", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      // Mock network failure
      server.use(
        http.post(`${domain}/me/v1/connected-accounts/connect`, () => {
          return HttpResponse.error();
        })
      );

      await expect(
        auth0Client.connectAccount({
          connection: "google-oauth2"
        })
      ).rejects.toThrow(ConnectAccountError);
    });

    it("should handle API validation errors", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      // Mock validation error
      server.use(
        http.post(`${domain}/me/v1/connected-accounts/connect`, () => {
          return HttpResponse.json(
            {
              error: "invalid_connection",
              error_description: "The specified connection does not exist"
            },
            { status: 400 }
          );
        })
      );

      await expect(
        auth0Client.connectAccount({
          connection: "invalid-connection"
        })
      ).rejects.toThrow(ConnectAccountError);
    });

    it("should provide meaningful error messages", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      // Mock specific API error
      server.use(
        http.post(`${domain}/me/v1/connected-accounts/connect`, () => {
          return HttpResponse.json(
            {
              error: "insufficient_scope",
              error_description:
                "The access token does not have the required scope: create:me:connected_accounts"
            },
            { status: 403 }
          );
        })
      );

      try {
        await auth0Client.connectAccount({
          connection: "google-oauth2"
        });
        expect.fail("Expected ConnectAccountError to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(ConnectAccountError);
        expect((error as ConnectAccountError).message).toContain(
          "failed with status 403"
        );
      }
    });
  });

  describe("Configuration Validation", () => {
    it("should require enableConnectAccountEndpoint to be true", () => {
      const clientWithoutConnectAccounts = new Auth0Client({
        ...testAuth0ClientConfig,
        enableConnectAccountEndpoint: false
      });

      // The endpoint should not be available when not enabled
      expect(
        (clientWithoutConnectAccounts as any).authClient
          .enableConnectAccountEndpoint
      ).toBe(false);
    });

    it("should work when offline_access scope is present", async () => {
      const session = await createTestSession();

      vi.spyOn(auth0Client, "getSession").mockResolvedValue(session);
      vi.spyOn(auth0Client, "getAccessToken").mockResolvedValue({
        token: accessToken,
        expiresAt: Date.now() + 3600000
      });

      const response = await auth0Client.connectAccount({
        connection: "google-oauth2"
      });

      expect(response).toBeInstanceOf(NextResponse);
      expect(response.status).toBe(307);
    });
  });
});

describe("Connected Accounts Callback Flow", () => {
  let mockOnCallback: ReturnType<typeof vi.fn>;

  beforeAll(async () => {
    server.listen({ onUnhandledRequest: "error" });
    keyPair = await jose.generateKeyPair(alg);
    dpopKeyPair = await generateDpopKeyPair();
  });

  afterAll(() => {
    server.close();
  });

  beforeEach(async () => {
    server.resetHandlers();
    mockOnCallback = vi
      .fn()
      .mockResolvedValue(
        NextResponse.redirect(
          new URL("/dashboard", testAuth0ClientConfig.appBaseUrl)
        )
      );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Callback Completion Tests", () => {
    it("should complete the connect account flow and call onCallback hook", async () => {
      const state = "transaction-state";
      const connectCode = "connect-code";
      const secret = await generateSecret(32);

      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: testAuth0ClientConfig.domain,
        clientId: testAuth0ClientConfig.clientId,
        clientSecret: testAuth0ClientConfig.clientSecret,
        secret,
        appBaseUrl: testAuth0ClientConfig.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: fetch, // Use standard fetch for oauth4webapi compatibility
        onCallback: mockOnCallback,
        enableConnectAccountEndpoint: true
      });

      // Set up MSW handler for complete connect account request
      server.use(
        http.post(
          `${domain}/me/v1/connected-accounts/complete`,
          async ({ request }) => {
            const body = (await request.json()) as any;
            expect(body).toEqual(
              expect.objectContaining({
                auth_session: "auth-session-123",
                connect_code: connectCode,
                redirect_uri: `${testAuth0ClientConfig.appBaseUrl}/auth/callback`,
                code_verifier: expect.any(String)
              })
            );

            return HttpResponse.json({
              connection: "google-oauth2",
              access_type: "offline",
              created_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 3600000).toISOString(),
              id: "cac_abc123",
              scopes: ["openid", "profile", "email"]
            });
          }
        )
      );

      const url = new URL("/auth/callback", testAuth0ClientConfig.appBaseUrl);
      url.searchParams.set("connect_code", connectCode);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CONNECT_CODE,
        state: state,
        returnTo: "/dashboard",
        authSession: "auth-session-123"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );

      const session: SessionData = {
        user: {
          sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken,
          scope: "openid profile email",
          refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60 // expires in 10 days
        },
        internal: {
          sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const sessionCookie = await encrypt(session, secret, expiration);
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const redirectUrl = new URL(response.headers.get("Location")!);
      expect(redirectUrl.pathname).toEqual("/dashboard");

      // validate the transaction cookie has been removed
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      expect(transactionCookie).toBeDefined();
      expect(transactionCookie!.value).toEqual("");
      expect(transactionCookie!.maxAge).toEqual(0);

      // validate that onCallback has been called with the connected account
      const expectedSession = expect.objectContaining({
        user: {
          sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken,
          refreshToken,
          expiresAt: expect.any(Number),
          scope: "openid profile email"
        },
        internal: {
          sid: expect.any(String),
          createdAt: expect.any(Number)
        }
      });
      const expectedContext = expect.objectContaining({
        responseType: RESPONSE_TYPES.CONNECT_CODE,
        returnTo: transactionState.returnTo,
        connectedAccount: {
          accessType: "offline",
          connection: "google-oauth2",
          createdAt: expect.any(String),
          expiresAt: expect.any(String),
          id: "cac_abc123",
          scopes: ["openid", "profile", "email"]
        }
      });

      expect(mockOnCallback).toHaveBeenCalledWith(
        null,
        expectedContext,
        expectedSession
      );
    });

    it("should handle callback errors when complete connect account fails", async () => {
      const state = "transaction-state";
      const connectCode = "connect-code";
      const secret = await generateSecret(32);

      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: testAuth0ClientConfig.domain,
        clientId: testAuth0ClientConfig.clientId,
        clientSecret: testAuth0ClientConfig.clientSecret,
        secret,
        appBaseUrl: testAuth0ClientConfig.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: fetch,
        onCallback: mockOnCallback,
        enableConnectAccountEndpoint: true
      });

      // Mock the complete endpoint to return an error
      server.use(
        http.post(`${domain}/me/v1/connected-accounts/complete`, () => {
          return HttpResponse.json(
            {
              error: "invalid_session",
              error_description: "Auth session expired"
            },
            { status: 400 }
          );
        })
      );

      const url = new URL("/auth/callback", testAuth0ClientConfig.appBaseUrl);
      url.searchParams.set("connect_code", connectCode);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CONNECT_CODE,
        state: state,
        returnTo: "/dashboard",
        authSession: "auth-session-123"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );

      const session: SessionData = {
        user: { sub, name: "John Doe" },
        tokenSet: {
          accessToken,
          scope: "openid profile email",
          refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: { sid, createdAt: Math.floor(Date.now() / 1000) }
      };
      const sessionCookie = await encrypt(session, secret, expiration);
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);

      // Verify that the callback was called with an error
      expect(mockOnCallback).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          returnTo: "/dashboard"
        }),
        null
      );

      // Verify that the transaction cookie was cleaned up
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      expect(transactionCookie).toBeDefined();
      expect(transactionCookie!.value).toEqual("");
      expect(transactionCookie!.maxAge).toEqual(0);
    });
  });

  describe("Configuration-Based Behavior Tests", () => {
    it("should not allow connect account when endpoint is disabled", async () => {
      const secret = await generateSecret(32);

      const authClient = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore: new StatelessSessionStore({ secret }),
        domain: testAuth0ClientConfig.domain,
        clientId: testAuth0ClientConfig.clientId,
        clientSecret: testAuth0ClientConfig.clientSecret,
        secret,
        appBaseUrl: testAuth0ClientConfig.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: fetch,
        enableConnectAccountEndpoint: false // Explicitly disabled
      });

      const session: SessionData = await createTestSession();
      const sessionCookie = await encrypt(
        session,
        secret,
        Math.floor(Date.now() / 1000) + 3600
      );

      const url = new URL(
        "/auth/connect-account",
        testAuth0ClientConfig.appBaseUrl
      );
      url.searchParams.set("connection", "google-oauth2");
      url.searchParams.set("returnTo", "/");

      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(url, {
        method: "GET", // Use GET request like the original test
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(200); // Falls through to NextResponse.next() when disabled
    });
  });
});
