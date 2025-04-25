/**
 * @fileoverview
 * Tests for access token refresh logic in both AuthClient and Auth0Client.
 *
 * These tests verify that when an access token is expired or a refresh is forced:
 * 1. `AuthClient.getTokenSet` correctly uses the refresh token grant to obtain a new
 *    token set from the authorization server.
 * 2. `Auth0Client.getAccessToken` correctly utilizes the internal `AuthClient.getTokenSet`
 *    to refresh the token and handles session saving appropriately for different
 *    Next.js router contexts (Pages Router vs App Router).
 *
 * Mocking Strategy:
 * - A mock authorization server (`getMockAuthorizationServer`) is implemented using `vi.fn()`
 *   to simulate the behavior of the OIDC token endpoint (`/oauth/token`) and discovery
 *   endpoints (`/.well-known/...`). This mock function replaces the actual `fetch` calls.
 * - For `Auth0Client.getAccessToken` tests, direct injection of the mock fetch isn't feasible.
 *   Instead, `vi.spyOn(AuthClient.prototype, 'getTokenSet')` is used. The spy's implementation
 *   delegates the call to a real `AuthClient` instance that *is* configured with the mock fetch.
 *   A temporary restore/re-apply mechanism within the spy implementation prevents infinite recursion.
 */

import { NextRequest, NextResponse } from "next/server";
import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../test/utils";
import { SessionData, TokenSet } from "../types";
import { AuthClient } from "./auth-client";
import { Auth0Client } from "./client";
import { StatelessSessionStore } from "./session/stateless-session-store";
import { TransactionStore } from "./transaction-store";

// Basic constants for testing
const DEFAULT = {
  domain: "https://op.example.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.org",
  secret: "test-secret-long-enough-for-hs256",
  alg: "RS256",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token",
  idToken: "test-id-token",
  sub: "test-sub",
  sid: "test-sid",
  scope: "openid profile email"
};

/**
 * Creates a simplified mock authorization server.
 *
 * This function returns a `vi.fn()` mock that simulates the fetch function,
 * specifically handling requests to the token, OpenID configuration, and JWKS endpoints.
 * It allows configuring the details of the refreshed tokens returned by the token endpoint.
 *
 * @param {object} options - Configuration for the mock responses.
 * @param {string} [options.refreshedAccessToken="refreshed-access-token"] - Access token to return on refresh.
 * @param {number} [options.refreshedExpiresIn=3600] - Expires_in value to return on refresh.
 * @param {string} [options.refreshedRefreshToken="refreshed-refresh-token"] - Refresh token to return on refresh.
 * @returns {Promise<vi.Mock>} A Vitest mock function simulating `fetch`.
 */
async function getMockAuthorizationServer({
  refreshedAccessToken = "refreshed-access-token",
  refreshedExpiresIn = 3600,
  refreshedRefreshToken = "refreshed-refresh-token"
}: {
  refreshedAccessToken?: string;
  refreshedExpiresIn?: number;
  refreshedRefreshToken?: string;
} = {}) {
  const keyPair = await jose.generateKeyPair(DEFAULT.alg);
  const _authorizationServerMetadata = {
    issuer: DEFAULT.domain,
    token_endpoint: `${DEFAULT.domain}/oauth/token`,
    jwks_uri: `${DEFAULT.domain}/.well-known/jwks.json`
  };

  return vi.fn(
    async (
      input: RequestInfo | URL,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _init?: RequestInit
    ): Promise<Response> => {
      let url: URL;
      if (input instanceof Request) {
        url = new URL(input.url);
      } else {
        url = new URL(input);
      }

      if (url.pathname === "/oauth/token") {
        // For refresh token grant, generate a new ID token if needed
        const jwt = await new jose.SignJWT({
          sid: DEFAULT.sid,
          auth_time: Date.now(),
          nonce: "nonce-value" // Nonce might not be strictly needed for refresh, but included for completeness
        })
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject(DEFAULT.sub)
          .setIssuedAt()
          .setIssuer(_authorizationServerMetadata.issuer)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime("2h")
          .sign(keyPair.privateKey);

        return Response.json({
          token_type: "Bearer",
          access_token: refreshedAccessToken,
          refresh_token: refreshedRefreshToken,
          id_token: jwt, // Always use the generated valid JWT
          expires_in: refreshedExpiresIn,
          scope: DEFAULT.scope
        });
      }

      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json(_authorizationServerMetadata);
      }

      if (url.pathname === "/.well-known/jwks.json") {
        const jwk = await jose.exportJWK(keyPair.publicKey);
        return Response.json({ keys: [jwk] });
      }

      return new Response(null, { status: 404 });
    }
  );
}

/**
 * Tests specifically for the `AuthClient.getTokenSet` method's refresh logic.
 */
describe("AuthClient - getTokenSet", () => {
  it("should return a refreshed token set when forceRefresh is true", async () => {
    const secret = await generateSecret(32);
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });

    const initialExpiresAt = Math.floor(Date.now() / 1000) - 60; // Expired 1 minute ago
    const initialTokenSet: TokenSet = {
      accessToken: "initial-access-token",
      refreshToken: "initial-refresh-token",
      idToken: "initial-id-token",
      scope: "openid profile",
      expiresAt: initialExpiresAt
    };

    const expectedRefreshedAccessToken = "authclient-refreshed-access-token";
    const expectedRefreshedRefreshToken = "authclient-refreshed-refresh-token";
    const expectedRefreshedExpiresIn = 7200; // 2 hours

    const mockFetch = await getMockAuthorizationServer({
      refreshedAccessToken: expectedRefreshedAccessToken,
      refreshedRefreshToken: expectedRefreshedRefreshToken,
      refreshedExpiresIn: expectedRefreshedExpiresIn
    });

    const authClient = new AuthClient({
      transactionStore,
      sessionStore,
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      secret,
      appBaseUrl: DEFAULT.appBaseUrl,
      fetch: mockFetch
    });

    const [error, updatedTokenSet] = await authClient.getTokenSet(
      initialTokenSet,
      true
    ); // forceRefresh = true

    expect(error).toBeNull();
    expect(updatedTokenSet).not.toBeNull();

    // Check specific fields of the refreshed token set
    expect(updatedTokenSet?.accessToken).toBe(expectedRefreshedAccessToken);
    expect(updatedTokenSet?.refreshToken).toBe(expectedRefreshedRefreshToken);
    expect(updatedTokenSet?.scope).toBe(initialTokenSet.scope); // Check against the original scope, as it's not updated by refresh
    expect(updatedTokenSet?.idToken).toEqual(expect.any(String)); // ID token should be present (newly generated or provided)
    expect(updatedTokenSet?.expiresAt).toBeGreaterThan(initialExpiresAt);
    // Check if expiresAt is roughly correct (allowing for clock skew/test execution time)
    const expectedExpiresAt =
      Math.floor(Date.now() / 1000) + expectedRefreshedExpiresIn;
    expect(updatedTokenSet?.expiresAt).toBeGreaterThanOrEqual(
      expectedExpiresAt - 5
    ); // Allow 5s buffer
    expect(updatedTokenSet?.expiresAt).toBeLessThanOrEqual(
      expectedExpiresAt + 5
    ); // Allow 5s buffer

    // Verify the mock fetch was called for the token endpoint
    const fetchCalls = mockFetch.mock.calls;
    const tokenEndpointCall = fetchCalls.find((call) => {
      let urlString: string;
      if (call[0] instanceof URL) {
        urlString = call[0].toString();
      } else if (call[0] instanceof Request) {
        urlString = call[0].url;
      } else {
        // string
        urlString = call[0];
      }
      return urlString.endsWith("/oauth/token");
    });
    expect(tokenEndpointCall).toBeDefined();
  });
});

/**
 * Tests for the `Auth0Client.getAccessToken` method, covering both
 * Pages Router and App Router overloads, specifically focusing on refresh logic.
 */
describe("Auth0Client - getAccessToken", () => {
  let secret = "";
  let mockFetch = vi.fn();
  let realAuthClientWithMockFetch: AuthClient;
  let getTokenSetSpy: any;

  /**
   * Common setup executed before each test in this describe block.
   * - Generates a secret.
   * - Creates a mock fetch function using `getMockAuthorizationServer`.
   * - Creates a real `AuthClient` instance configured with the mock fetch.
   * - Spies on `AuthClient.prototype.getTokenSet` and sets up a mock implementation
   *   that delegates to the `realAuthClientWithMockFetch` instance, using a
   *   restore/re-apply mechanism to avoid infinite recursion.
   */
  beforeEach(async () => {
    secret = await generateSecret(32);

    // 1. Create the mock fetch instance for the test block
    const expectedRefreshedAccessToken =
      "getAccessToken-refreshed-access-token";
    const expectedRefreshedRefreshToken =
      "getAccessToken-refreshed-refresh-token";
    const expectedRefreshedExpiresIn = 7200;
    mockFetch = await getMockAuthorizationServer({
      refreshedAccessToken: expectedRefreshedAccessToken,
      refreshedRefreshToken: expectedRefreshedRefreshToken,
      refreshedExpiresIn: expectedRefreshedExpiresIn
    });

    // 2. Create a real AuthClient instance that USES the mockFetch
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    realAuthClientWithMockFetch = new AuthClient({
      transactionStore,
      sessionStore,
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      secret,
      appBaseUrl: DEFAULT.appBaseUrl,
      fetch: mockFetch
    });

    // 3. Spy on AuthClient.prototype.getTokenSet and delegate, avoiding recursion
    getTokenSetSpy = vi.spyOn(AuthClient.prototype, "getTokenSet");
    const mockImplementation = async (
      tokenSet: TokenSet,
      forceRefresh?: boolean | undefined
    ) => {
      getTokenSetSpy.mockRestore();
      try {
        const result = await realAuthClientWithMockFetch.getTokenSet(
          tokenSet,
          forceRefresh
        );
        getTokenSetSpy.mockImplementation(mockImplementation);
        return result;
      } catch (error) {
        getTokenSetSpy.mockImplementation(mockImplementation);
        throw error;
      }
    };
    getTokenSetSpy.mockImplementation(mockImplementation);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Test Case: Pages Router Overload - getAccessToken(req, res, options)
   * Verifies that when called with req/res objects and refresh: true,
   * it refreshes the token and saves the updated session.
   */
  it("should refresh token for pages-router overload when refresh is true", async () => {
    const initialExpiresAt = Math.floor(Date.now() / 1000) - 60;
    const initialTokenSet: TokenSet = {
      accessToken: "initial-pages-access-token",
      refreshToken: "initial-pages-refresh-token",
      idToken: "initial-pages-id-token",
      scope: "openid profile pages", // Different scope for clarity
      expiresAt: initialExpiresAt
    };
    const initialSession: SessionData = {
      user: { sub: DEFAULT.sub },
      tokenSet: initialTokenSet,
      internal: { sid: DEFAULT.sid, createdAt: Date.now() }
    };

    // Mock Auth0Client specific methods
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );
    const mockSaveToSession = vi
      .spyOn(Auth0Client.prototype as any, "saveToSession")
      .mockResolvedValue(undefined);

    // --- Execution ---
    const auth0Client = new Auth0Client({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      secret: secret
    });

    const mockReq = new NextRequest("https://example.com/api/pages-test");
    const mockRes = new NextResponse();

    // Use expected values from beforeEach setup
    const expectedRefreshedAccessToken =
      "getAccessToken-refreshed-access-token";
    const expectedRefreshedRefreshToken =
      "getAccessToken-refreshed-refresh-token";
    const expectedRefreshedExpiresIn = 7200;

    const result = await auth0Client.getAccessToken(mockReq, mockRes, {
      refresh: true
    });

    // --- Assertions ---

    // 1. Assert the returned access token details
    expect(result).not.toBeNull();
    expect(result?.token).toBe(expectedRefreshedAccessToken);
    expect(result?.expiresAt).toBeGreaterThan(initialExpiresAt);
    const expectedExpiresAtRough =
      Math.floor(Date.now() / 1000) + expectedRefreshedExpiresIn;
    expect(result?.expiresAt).toBeGreaterThanOrEqual(
      expectedExpiresAtRough - 5
    );
    expect(result?.expiresAt).toBeLessThanOrEqual(expectedExpiresAtRough + 5);
    expect(result?.scope).toBe(initialTokenSet.scope); // Scope remains initial

    // 2. Assert saveToSession was called (Pages Router specific)
    expect(mockSaveToSession).toHaveBeenCalledOnce();
    const savedSession = mockSaveToSession.mock.calls[0][0] as SessionData;
    expect(savedSession.tokenSet.accessToken).toBe(
      expectedRefreshedAccessToken
    );
    expect(savedSession.tokenSet.refreshToken).toBe(
      expectedRefreshedRefreshToken
    );
    expect(savedSession.tokenSet.expiresAt).toBe(result?.expiresAt);
    expect(savedSession.tokenSet.scope).toBe(initialTokenSet.scope);

    // 3. Assert mockFetch was called
    const fetchCalls = mockFetch.mock.calls;
    expect(fetchCalls.length).toBeGreaterThan(0);
    const tokenEndpointCall = fetchCalls.find((call: any) => {
      let urlString: string;
      if (call[0] instanceof URL) {
        urlString = call[0].toString();
      } else if (call[0] instanceof Request) {
        urlString = call[0].url;
      } else {
        urlString = call[0];
      }
      return urlString.endsWith("/oauth/token");
    });
    expect(tokenEndpointCall).toBeDefined();
  });

  /**
   * Test Case: App Router Overload - getAccessToken(options)
   * Verifies that when called without req/res objects and refresh: true,
   * it refreshes the token. Currently, it *also* calls saveToSession,
   * so the test asserts this observed behavior.
   */
  it("should refresh token for app-router overload when refresh is true", async () => {
    const initialExpiresAt = Math.floor(Date.now() / 1000) - 60;
    const initialTokenSet: TokenSet = {
      accessToken: "initial-app-access-token",
      refreshToken: "initial-app-refresh-token",
      idToken: "initial-app-id-token",
      scope: "openid profile app", // Different scope for clarity
      expiresAt: initialExpiresAt
    };
    const initialSession: SessionData = {
      user: { sub: DEFAULT.sub },
      tokenSet: initialTokenSet,
      internal: { sid: DEFAULT.sid, createdAt: Date.now() }
    };

    // Mock Auth0Client specific methods
    vi.spyOn(Auth0Client.prototype as any, "getSession").mockResolvedValue(
      initialSession
    );
    // IMPORTANT: saveToSession should NOT be called in app-router mode
    const mockSaveToSession = vi.spyOn(
      Auth0Client.prototype as any,
      "saveToSession"
    );

    // --- Execution ---
    const auth0Client = new Auth0Client({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      secret: secret
    });

    // Use expected values from beforeEach setup
    const expectedRefreshedAccessToken =
      "getAccessToken-refreshed-access-token";
    const expectedRefreshedRefreshToken =
      "getAccessToken-refreshed-refresh-token";
    const expectedRefreshedExpiresIn = 7200;

    const result = await auth0Client.getAccessToken({
      refresh: true
    });

    // --- Assertions ---

    // 1. Assert the returned access token details
    expect(result).not.toBeNull();
    expect(result?.token).toBe(expectedRefreshedAccessToken);
    expect(result?.expiresAt).toBeGreaterThan(initialExpiresAt);
    const expectedExpiresAtRough =
      Math.floor(Date.now() / 1000) + expectedRefreshedExpiresIn;
    expect(result?.expiresAt).toBeGreaterThanOrEqual(
      expectedExpiresAtRough - 5
    );
    expect(result?.expiresAt).toBeLessThanOrEqual(expectedExpiresAtRough + 5);
    expect(result?.scope).toBe(initialTokenSet.scope); // Scope remains initial

    // 2. Assert saveToSession WAS called (matches current behavior)
    expect(mockSaveToSession).toHaveBeenCalledOnce();
    const savedSession = mockSaveToSession.mock.calls[0][0] as SessionData;
    expect(savedSession.tokenSet.accessToken).toBe(
      expectedRefreshedAccessToken
    );
    expect(savedSession.tokenSet.refreshToken).toBe(
      expectedRefreshedRefreshToken
    );
    expect(savedSession.tokenSet.expiresAt).toBe(result?.expiresAt);
    expect(savedSession.tokenSet.scope).toBe(initialTokenSet.scope);

    // 3. Assert mockFetch was called
    const fetchCalls = mockFetch.mock.calls;
    expect(fetchCalls.length).toBeGreaterThan(0);
    const tokenEndpointCall = fetchCalls.find((call: any) => {
      let urlString: string;
      if (call[0] instanceof URL) {
        urlString = call[0].toString();
      } else if (call[0] instanceof Request) {
        urlString = call[0].url;
      } else {
        urlString = call[0];
      }
      return urlString.endsWith("/oauth/token");
    });
    expect(tokenEndpointCall).toBeDefined();
  });
});
