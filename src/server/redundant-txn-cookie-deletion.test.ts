/* eslint-disable @typescript-eslint/no-unused-vars */
import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import * as oauth from "oauth4webapi";
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

import { InvalidStateError, MissingStateError } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { AuthClient, AuthClientOptions } from "./auth-client.js";
import {
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "./cookies.js";
import {
  AbstractSessionStore,
  SessionStoreOptions
} from "./session/abstract-session-store.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Only mock specific oauth4webapi functions that need predictable values
vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    // Mock PKCE generation functions for predictable test values
    generateRandomState: vi.fn(),
    generateRandomNonce: vi.fn(),
    generateRandomCodeVerifier: vi.fn(),
    calculatePKCECodeChallenge: vi.fn(),
    // Mock HTTP-related functions for MSW integration
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    // Mock response validation since it's pure function processing
    validateAuthResponse: vi.fn(),
    // Mock ID token validation for predictable claims
    getValidatedIdTokenClaims: vi.fn(),
    // Mock token processing to avoid complex JWT validation
    processAuthorizationCodeResponse: vi.fn(),
    // Mock additional functions for full callback support
    authorizationCodeGrantRequest: vi.fn()
  };
});

// Test constants
const domain = "test.auth0.com";
const clientId = "test-client-id";

// Generate test keys for JWT signing
let keyPair: jose.GenerateKeyPairResult;

// Helper function to create a valid ID token
const createValidIdToken = async (claims: any = {}) => {
  if (!keyPair) {
    keyPair = await jose.generateKeyPair("RS256");
  }

  return await new jose.SignJWT({
    sub: "user123",
    sid: "sid123",
    nonce: "test-nonce",
    aud: clientId,
    iss: `https://${domain}/`,
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...claims
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(keyPair.privateKey);
};

// MSW handlers for mocking HTTP requests
const handlers = [
  // OIDC Discovery Endpoint
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      token_endpoint: `https://${domain}/oauth/token`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      end_session_endpoint: `https://${domain}/v2/logout`
    });
  }),
  // JWKS Endpoint
  http.get(`https://${domain}/.well-known/jwks.json`, async () => {
    if (!keyPair) {
      keyPair = await jose.generateKeyPair("RS256");
    }
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-id", use: "sig" }]
    });
  }),
  // Token Endpoint
  http.post(`https://${domain}/oauth/token`, async () => {
    const idToken = await createValidIdToken();
    return HttpResponse.json({
      access_token: "access_token_123",
      id_token: idToken,
      refresh_token: "refresh_token_123",
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid profile email"
    });
  })
];

const server = setupServer(...handlers);

beforeAll(async () => {
  // Initialize key pair for JWT signing
  keyPair = await jose.generateKeyPair("RS256");
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

class TestSessionStore extends AbstractSessionStore {
  constructor(config: SessionStoreOptions) {
    super(config);
  }
  async get(
    _reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null> {
    return null;
  }
  async set(
    _reqCookies: RequestCookies | ReadonlyRequestCookies,
    _resCookies: ResponseCookies,
    _session: SessionData,
    _isNew?: boolean | undefined
  ): Promise<void> {
    // Empty implementation for testing
  }
  async delete(
    _reqCookies: RequestCookies | ReadonlyRequestCookies,
    _resCookies: ResponseCookies
  ): Promise<void> {
    // Empty implementation for testing
  }
}

const baseOptions: Partial<AuthClientOptions> = {
  domain,
  clientId,
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  secret: "a-sufficiently-long-secret-for-testing",
  routes: getDefaultRoutes()
};

describe("Ensure that redundant transaction cookies are deleted from auth-client methods", () => {
  let authClient: AuthClient;
  let mockTransactionStoreInstance: TransactionStore;
  let mockSessionStoreInstance: TestSessionStore;
  let secret: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.restoreAllMocks();

    secret = await generateSecret(32);

    // Create real transaction store for integration testing
    mockTransactionStoreInstance = new TransactionStore({
      secret,
      enableParallelTransactions: true
    });

    const testSessionStoreOptions: SessionStoreOptions = {
      secret: "test-secret",
      cookieOptions: { name: "__session", path: "/", sameSite: "lax" }
    };
    mockSessionStoreInstance = new TestSessionStore(testSessionStoreOptions);

    // Mock session store methods for controlled testing
    mockSessionStoreInstance.get = vi.fn().mockResolvedValue({
      user: { sub: "user123" },
      internal: { sid: "sid123" },
      tokenSet: { idToken: "idtoken123" }
    });
    mockSessionStoreInstance.delete = vi.fn().mockResolvedValue(undefined);
    mockSessionStoreInstance.set = vi.fn().mockResolvedValue(undefined);

    authClient = new AuthClient({
      ...baseOptions,
      secret,
      sessionStore: mockSessionStoreInstance as any,
      transactionStore: mockTransactionStoreInstance
    } as AuthClientOptions);

    // Only mock functions that need predictable values for testing
    // HTTP requests will be handled by MSW handlers above
    vi.mocked(oauth.generateRandomState).mockReturnValue("test-state");
    vi.mocked(oauth.generateRandomNonce).mockReturnValue("test-nonce");
    vi.mocked(oauth.generateRandomCodeVerifier).mockReturnValue("cv");
    vi.mocked(oauth.calculatePKCECodeChallenge).mockResolvedValue("cc");

    // Restore all oauth4webapi mocks with proper return values
    vi.mocked(oauth.validateAuthResponse).mockReturnValue(
      new URLSearchParams("code=auth_code&state=test-state")
    );

    // Mock discovery for MSW integration
    vi.mocked(oauth.discoveryRequest).mockResolvedValue(new Response());
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      token_endpoint: `https://${domain}/oauth/token`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      end_session_endpoint: `https://${domain}/v2/logout`
    } as any);

    // Mock token request for MSW integration
    vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue(
      new Response()
    );
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      token_type: "Bearer",
      access_token: "access_token_123",
      id_token: await createValidIdToken(),
      refresh_token: "refresh_token_789",
      expires_in: 3600,
      scope: "openid profile email"
    } as any);

    // We still need to mock these since JWT validation is complex and we want predictable results
    vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
      sub: "user123",
      sid: "sid123",
      nonce: "test-nonce",
      aud: clientId,
      iss: `https://${domain}/`,
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 3600
    });

    // Mock the token processing response to avoid JWT validation complexity
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      token_type: "Bearer",
      access_token: "access_token_123",
      id_token: await createValidIdToken(),
      refresh_token: "refresh_token_789",
      expires_in: 3600,
      scope: "openid profile email"
    } as oauth.TokenEndpointResponse);
  });

  describe("handleLogout", () => {
    it("should delete session cookie but no transaction cookies if none exist", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);

      // Check that transaction cookies were cleaned up (by checking response cookies)
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith("__txn_") &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      // No transaction cookies to delete, but deleteAll should still be called
      expect(deletedTxnCookies.length).toBe(0);

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });

    it("should delete session cookie AND call deleteAll for transaction cookies", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");
      req.cookies.set("__txn_state1", "txn-value1");
      req.cookies.set("__txn_state2", "txn-value2");
      req.cookies.set("other_cookie", "other-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);

      // Check that transaction cookies were deleted
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith("__txn_") &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedTxnCookies.length).toBeGreaterThan(0);
      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });

    it("should call deleteAll for transaction cookies even if no session exists", async () => {
      mockSessionStoreInstance.get = vi.fn().mockResolvedValue(null);
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__txn_state1", "txn-value1");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);

      // Check that transaction cookies were deleted
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith("__txn_") &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedTxnCookies.length).toBeGreaterThan(0);
      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });

    it("should respect custom transaction cookie prefix when calling deleteAll", async () => {
      const customPrefix = "__my_txn_";
      const customTxnStore = new TransactionStore({
        secret,
        enableParallelTransactions: true,
        cookieOptions: { prefix: customPrefix }
      });

      authClient = new AuthClient({
        ...baseOptions,
        secret,
        sessionStore: mockSessionStoreInstance as any,
        transactionStore: customTxnStore
      } as AuthClientOptions);

      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");
      req.cookies.set(`${customPrefix}state1`, "txn-value1");
      req.cookies.set("__txn_state2", "default-prefix-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);

      // Should only delete cookies with the custom prefix
      const deletedCustomTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith(customPrefix) &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedCustomTxnCookies.length).toBeGreaterThan(0);
      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });
  });

  describe("handleCallback", () => {
    beforeEach(() => {
      // Mock the transaction store get method to return valid transaction state
      vi.spyOn(mockTransactionStoreInstance, "get").mockResolvedValue({
        payload: {
          state: "test-state",
          nonce: "test-nonce",
          codeVerifier: "cv",
          responseType: "code",
          returnTo: "/"
        },
        protectedHeader: {}
      } as any);
    });

    it("should delete the correct transaction cookie on success", async () => {
      // First, do a login to get proper state
      const loginReq = new NextRequest("http://localhost:3000/api/auth/login");
      const loginRes = await authClient.handleLogin(loginReq);

      // Extract the state from the redirect URL
      const redirectUrl = new URL(loginRes.headers.get("Location")!);
      const state = redirectUrl.searchParams.get("state")!;

      // Get the transaction cookie that was set
      const txnCookie = loginRes.cookies.get(`__txn_${state}`);
      expect(txnCookie).toBeDefined();

      // Now create the callback request
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
      );

      // Add the transaction cookie to the callback request
      if (txnCookie) {
        req.cookies.set(`__txn_${state}`, txnCookie.value);
      }

      // Now test the callback
      const res = await authClient.handleCallback(req);

      // Verify transaction was retrieved and deleted
      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );

      // Check that transaction cookie was deleted
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name === `__txn_${state}` &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedTxnCookies.length).toBe(1);
      expect(mockSessionStoreInstance.set).toHaveBeenCalledTimes(1);
      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
      expect(res.headers.get("location")).toBe("http://localhost:3000/");
    });

    it("should NOT delete transaction cookie on InvalidStateError", async () => {
      const state = "invalid-state";
      vi.spyOn(mockTransactionStoreInstance, "get").mockResolvedValue(null);
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
      );

      const res = await authClient.handleCallback(req);

      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );

      // Check that no transaction cookies were deleted
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith("__txn_") &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedTxnCookies.length).toBe(0);
      expect(mockSessionStoreInstance.set).not.toHaveBeenCalled();
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain(new InvalidStateError().message);
    });

    it("should NOT delete transaction cookie on MissingStateError", async () => {
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code`
      );

      const res = await authClient.handleCallback(req);

      expect(mockTransactionStoreInstance.get).not.toHaveBeenCalled();

      // Check that no transaction cookies were deleted
      const deletedTxnCookies = res.cookies
        .getAll()
        .filter(
          (cookie) =>
            cookie.name.startsWith("__txn_") &&
            cookie.value === "" &&
            cookie.maxAge === 0
        );

      expect(deletedTxnCookies.length).toBe(0);
      expect(mockSessionStoreInstance.set).not.toHaveBeenCalled();
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain(new MissingStateError().message);
    });
  });

  // Integration tests for the v4 infinitely stacking cookies issue
  describe("v4 Infinitely Stacking Cookies - Integration Tests", () => {
    let statelessSessionStore: StatelessSessionStore;

    beforeEach(async () => {
      // Use real stateless session store for these integration tests
      statelessSessionStore = new StatelessSessionStore({ secret });

      authClient = new AuthClient({
        ...baseOptions,
        secret,
        sessionStore: statelessSessionStore,
        transactionStore: mockTransactionStoreInstance
      } as AuthClientOptions);
    });

    describe("Happy Path", () => {
      it("should clean up all transaction cookies after successful authentication", async () => {
        // Arrange: Create a login
        const loginReq = new NextRequest(
          "http://localhost:3000/api/auth/login"
        );
        const loginRes = await authClient.handleLogin(loginReq);

        // Extract the state from the redirect URL
        const redirectUrl = new URL(loginRes.headers.get("Location")!);
        const state = redirectUrl.searchParams.get("state")!;

        // Get the transaction cookie that was set
        const newTxnCookie = loginRes.cookies.get(`__txn_${state}`);
        expect(newTxnCookie).toBeDefined();

        // Simulate callback request with multiple existing transaction cookies
        const callbackReq = new NextRequest(
          `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
        );

        // Add the stale cookies to the callback request
        callbackReq.cookies.set("__txn_old_state_1", "old_value_1");
        callbackReq.cookies.set("__txn_old_state_2", "old_value_2");
        if (newTxnCookie) {
          callbackReq.cookies.set(`__txn_${state}`, newTxnCookie.value);
        }

        // Act: Handle the callback
        const callbackRes = await authClient.handleCallback(callbackReq);

        // Assert: Verify that ALL transaction cookies are cleaned up
        expect(callbackRes.status).toBeGreaterThanOrEqual(300); // Should redirect
        expect(callbackRes.status).toBeLessThan(400);

        // Check that all transaction cookies are being deleted (set to empty with maxAge 0)
        const deletedCookies = callbackRes.cookies
          .getAll()
          .filter(
            (cookie) =>
              cookie.name.startsWith("__txn_") &&
              cookie.value === "" &&
              cookie.maxAge === 0
          );

        // Should have cleaned up all transaction cookies
        expect(deletedCookies.length).toBeGreaterThan(0);

        // Verify a session cookie was set
        const sessionCookie = callbackRes.cookies.get("__session");
        expect(sessionCookie).toBeDefined();
        expect(sessionCookie?.value).not.toBe("");
      });
    });

    describe("Edge Cases", () => {
      it("should handle callback with no existing transaction cookies gracefully", async () => {
        // Create a login and get the state
        const loginReq = new NextRequest(
          "http://localhost:3000/api/auth/login"
        );
        const loginRes = await authClient.handleLogin(loginReq);

        const redirectUrl = new URL(loginRes.headers.get("Location")!);
        const state = redirectUrl.searchParams.get("state")!;

        // Handle callback with only the current transaction cookie
        const callbackReq = new NextRequest(
          `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
        );

        const txnCookie = loginRes.cookies.get(`__txn_${state}`);
        if (txnCookie) {
          callbackReq.cookies.set(`__txn_${state}`, txnCookie.value);
        }

        const callbackRes = await authClient.handleCallback(callbackReq);

        // Should still work normally
        expect(callbackRes.status).toBeGreaterThanOrEqual(300);
        expect(callbackRes.status).toBeLessThan(400);
      });

      it("should not interfere with non-transaction cookies", async () => {
        // Create a login
        const loginReq = new NextRequest(
          "http://localhost:3000/api/auth/login"
        );
        const loginRes = await authClient.handleLogin(loginReq);

        const redirectUrl = new URL(loginRes.headers.get("Location")!);
        const state = redirectUrl.searchParams.get("state")!;

        // Handle callback with mixed cookies
        const callbackReq = new NextRequest(
          `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
        );

        const txnCookie = loginRes.cookies.get(`__txn_${state}`);
        if (txnCookie) {
          callbackReq.cookies.set(`__txn_${state}`, txnCookie.value);
        }
        callbackReq.cookies.set("other_cookie", "should_not_be_deleted");
        callbackReq.cookies.set("user_pref", "also_should_remain");

        const callbackRes = await authClient.handleCallback(callbackReq);

        // Check that only transaction cookies are deleted
        const deletedCookies = callbackRes.cookies
          .getAll()
          .filter((cookie) => cookie.value === "" && cookie.maxAge === 0);

        const deletedTxnCookies = deletedCookies.filter((cookie) =>
          cookie.name.startsWith("__txn_")
        );
        const deletedOtherCookies = deletedCookies.filter(
          (cookie) =>
            !cookie.name.startsWith("__txn_") &&
            !cookie.name.startsWith("__session") &&
            cookie.name !== "appSession" // Ignore session-related cookies
        );

        expect(deletedTxnCookies.length).toBeGreaterThan(0);
        expect(deletedOtherCookies.length).toBe(0);
      });
    });

    describe("enableParallelTransactions: false", () => {
      it("should use single transaction cookie without state suffix", async () => {
        // Arrange: Create auth client with parallel transactions disabled
        const singleTxnTransactionStore = new TransactionStore({
          secret,
          enableParallelTransactions: false
        });

        const singleTxnAuthClient = new AuthClient({
          transactionStore: singleTxnTransactionStore,
          sessionStore: statelessSessionStore,
          ...baseOptions,
          secret
        } as AuthClientOptions);

        // Act: Create a login
        const loginReq = new NextRequest(
          "http://localhost:3000/api/auth/login"
        );
        const loginRes = await singleTxnAuthClient.handleLogin(loginReq);

        // Assert: Should use __txn_ without state suffix
        const txnCookies = loginRes.cookies
          .getAll()
          .filter((cookie) => cookie.name.startsWith("__txn_"));

        expect(txnCookies).toHaveLength(1);
        expect(txnCookies[0].name).toBe("__txn_"); // No state suffix when parallel transactions disabled
      });
    });

    describe("Transaction Store Integration", () => {
      it("should skip existence check when reqCookies is not provided in startInteractiveLogin", async () => {
        // This is an integration test to verify that startInteractiveLogin
        // calls save() without reqCookies, thus skipping the existence check

        // Arrange: Spy on the transaction store save method
        const saveSpy = vi.spyOn(mockTransactionStoreInstance, "save");

        // Act: Call startInteractiveLogin
        await authClient.startInteractiveLogin();

        // Assert: Verify save was called with only 2 parameters (no reqCookies)
        expect(saveSpy).toHaveBeenCalledTimes(1);
        const [resCookies, transactionState, reqCookies] =
          saveSpy.mock.calls[0];
        expect(resCookies).toBeDefined();
        expect(transactionState).toBeDefined();
        expect(reqCookies).toBeUndefined(); // Should be undefined for performance
      });
    });
  });
});
