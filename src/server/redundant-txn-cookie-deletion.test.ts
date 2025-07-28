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
  /**
   * Test Suite Purpose: These tests ensure proper transaction cookie lifecycle management
   * to prevent the "infinitely stacking cookies" bug that existed in v4.
   *
   * Background:
   * - OAuth flows use transaction cookies to maintain state between login and callback
   * - In v4, these cookies were not properly cleaned up, leading to accumulation
   * - Multiple failed/abandoned auth attempts would create dozens/hundreds of cookies
   * - This would eventually hit browser cookie limits and break authentication
   *
   * What we're testing:
   * 1. Successful auth flows properly clean up transaction cookies
   * 2. Failed auth flows don't corrupt existing transaction state
   * 3. Logout cleans up all auth-related cookies (session + transactions)
   * 4. Error conditions preserve other parallel authentication attempts
   * 5. Integration scenarios with real cookie accumulation
   *
   * Key principles:
   * - Clean up on success (remove used transaction cookies)
   * - Preserve on failure (don't break other auth attempts)
   * - Bulk cleanup on logout (clear all auth state)
   */
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
      /**
       * Test Purpose: Verify that logout properly cleans up session cookies and calls
       * transaction cleanup even when no transaction cookies exist.
       *
       * Why this matters:
       * - Logout should always attempt to clean up ALL auth-related state
       * - Even if no transaction cookies exist, the cleanup method should still be called
       * - This ensures consistent logout behavior regardless of current auth state
       * - Validates that logout doesn't break when there are no pending transactions
       */

      // Arrange: Create logout request with only a session cookie
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");

      // Act: Process the logout
      const res = await authClient.handleLogout(req);

      // Assert: Verify session cleanup occurred
      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);

      // Check that transaction cookie cleanup was attempted (even if none exist)
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
      /**
       * Test Purpose: Verify that logout cleans up both session and all transaction cookies
       * when multiple transaction cookies exist.
       *
       * Why this matters:
       * - This tests the main logout cleanup functionality with multiple pending transactions
       * - Demonstrates that logout clears ALL auth state, not just the session
       * - Important for security - ensures no auth state is left behind after logout
       * - Validates the bulk transaction cookie cleanup mechanism
       */

      // Arrange: Create logout request with session and multiple transaction cookies
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");
      req.cookies.set("__txn_state1", "txn-value1");
      req.cookies.set("__txn_state2", "txn-value2");
      req.cookies.set("other_cookie", "other-value"); // Non-auth cookie should be preserved

      // Act: Process the logout
      const res = await authClient.handleLogout(req);

      // Assert: Verify all auth-related cleanup occurred
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
      /**
       * Test Purpose: Verify that when OAuth callback succeeds, only the specific transaction
       * cookie for that authentication flow is deleted, not all transaction cookies.
       *
       * Why this matters:
       * - In successful auth flows, we should clean up the used transaction cookie
       * - But preserve other parallel authentication attempts that might be in progress
       * - This is the "happy path" that demonstrates proper transaction cookie lifecycle
       * - Validates that the state parameter correctly identifies which transaction to clean up
       */

      // Arrange: First, do a login to get proper state and transaction cookie
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

      // Act: Process the successful callback
      const res = await authClient.handleCallback(req);

      // Assert: Verify transaction was retrieved and processed
      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );

      // Check that the specific transaction cookie was deleted
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
      /**
       * Test Purpose: Verify that when an OAuth callback has an invalid/unknown state parameter,
       * the system does not delete transaction cookies to preserve other authentication flows.
       *
       * Why this matters:
       * - Invalid state could indicate a stale/corrupted request or potential attack
       * - The transaction store returns null when state is not found (expired or never existed)
       * - We should NOT delete cookies on this error to avoid breaking other valid auth attempts
       * - In parallel authentication scenarios, one invalid state shouldn't affect others
       */

      // Arrange: Set up scenario where transaction store can't find the state
      const state = "invalid-state";
      vi.spyOn(mockTransactionStoreInstance, "get").mockResolvedValue(null);
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
      );

      // Act: Handle callback with invalid state
      const res = await authClient.handleCallback(req);

      // Assert: Verify transaction store was queried but found nothing
      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );

      // Check that no transaction cookies were deleted (preserve other auth flows)
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
      /**
       * Test Purpose: Verify that when an OAuth callback is missing the required 'state' parameter,
       * the system fails gracefully without deleting any transaction cookies.
       *
       * Why this matters:
       * - The 'state' parameter is critical for CSRF protection in OAuth flows
       * - Missing state indicates a malformed request or potential attack
       * - We should NOT delete transaction cookies on errors to preserve other valid auth attempts
       * - This prevents breaking parallel authentication flows or user retry scenarios
       */

      // Arrange: Create callback request WITHOUT state parameter (this triggers MissingStateError)
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code`
        // Notice: deliberately missing &state=xyz parameter
      );

      // Act: Handle the malformed callback
      const res = await authClient.handleCallback(req);

      // Assert: Verify error handling behavior
      // Should not attempt to retrieve transaction since no state to look up
      expect(mockTransactionStoreInstance.get).not.toHaveBeenCalled();

      // Check that no transaction cookies were deleted (preserve for other auth flows)
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
    /**
     * Test Suite Purpose: These integration tests address a critical bug in v4 where transaction
     * cookies would accumulate infinitely, causing browser cookie limits to be exceeded.
     *
     * The Problem:
     * - In v4, failed or abandoned auth attempts would leave transaction cookies in the browser
     * - Each new auth attempt would create a new transaction cookie
     * - Over time, this would lead to hundreds of transaction cookies accumulating
     * - Eventually browsers would hit cookie limits and start dropping cookies randomly
     * - This would break the authentication flow entirely
     *
     * The Solution:
     * - Implement proper transaction cookie cleanup after successful authentication
     * - Ensure failed authentications don't leave stale cookies
     * - Add bulk cleanup methods for removing all transaction cookies when needed
     * - Support both single and parallel transaction modes
     */
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
        /**
         * Test Purpose: This is the main integration test that validates the fix for the
         * v4 infinitely stacking cookies bug in a realistic scenario.
         *
         * What this test simulates:
         * 1. User starts an auth flow (gets a transaction cookie)
         * 2. Browser has some stale transaction cookies from previous attempts
         * 3. User completes the auth flow successfully
         * 4. System should clean up ALL transaction cookies, not just the current one
         *
         * Why this is critical:
         * - This prevents the infinite accumulation of transaction cookies
         * - Ensures browsers don't hit cookie limits
         * - Maintains clean auth state after successful authentication
         * - Works with both current and legacy transaction cookies
         */

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
      /**
       * Edge Case Testing: These tests ensure the transaction cookie cleanup works
       * correctly in various edge scenarios that might occur in production.
       */
      it("should handle callback with no existing transaction cookies gracefully", async () => {
        /**
         * Test Purpose: Verify that the cleanup mechanism works correctly even when
         * there are no stale transaction cookies to clean up.
         *
         * Why this matters:
         * - Not all auth flows will have accumulated stale cookies
         * - The cleanup logic should be robust and not fail when there's nothing to clean
         * - This is a baseline test to ensure the happy path works in the simplest case
         */
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
        /**
         * Test Purpose: Verify that transaction cookie cleanup is surgical and only
         * affects transaction cookies, leaving other application cookies untouched.
         *
         * Why this matters:
         * - Applications often have other cookies for user preferences, analytics, etc.
         * - The cleanup mechanism should be precise and not have side effects
         * - This ensures the auth system doesn't interfere with other app functionality
         * - Validates that our cookie filtering logic is working correctly
         */
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
