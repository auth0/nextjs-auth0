import { NextRequest } from "next/server.js";
import * as oauth from "oauth4webapi";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthClient } from "../src/server/auth-client.js";
import { StatelessSessionStore } from "../src/server/session/stateless-session-store.js";
import { TransactionStore } from "../src/server/transaction-store.js";
import { generateSecret } from "../src/test/utils.js";

// Mock oauth4webapi module
vi.mock("oauth4webapi");

describe(`v4-infinitely-stacking-cookies - v4: Infinitely stacking cookies regression`, () => {
  let authClient: AuthClient;
  let transactionStore: TransactionStore;
  let sessionStore: StatelessSessionStore;
  let secret: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();

    secret = await generateSecret(32);
    transactionStore = new TransactionStore({
      secret,
      enableParallelTransactions: true
    });
    sessionStore = new StatelessSessionStore({ secret });

    authClient = new AuthClient({
      transactionStore,
      sessionStore,
      domain: "test.auth0.com",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      appBaseUrl: "http://localhost:3000",
      secret,
      routes: {
        login: "/api/auth/login",
        logout: "/api/auth/logout",
        callback: "/api/auth/callback"
      },
      fetch: vi.fn().mockImplementation((url) => {
        // Mock the token endpoint
        if (url.includes("/oauth/token")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                access_token: "access_token_123",
                id_token:
                  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJpc3MiOiJodHRwczovL3Rlc3QuYXV0aDAuY29tLyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDA3MjAwfQ.mock_signature",
                refresh_token: "refresh_token_123",
                token_type: "Bearer",
                expires_in: 3600,
                scope: "openid profile email"
              }),
              {
                headers: { "Content-Type": "application/json" }
              }
            )
          );
        }

        // Mock the JWKS endpoint
        if (url.includes("/.well-known/jwks.json")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                keys: [
                  {
                    kty: "RSA",
                    kid: "test-key-id",
                    use: "sig",
                    n: "mock_n_value",
                    e: "AQAB"
                  }
                ]
              }),
              {
                headers: { "Content-Type": "application/json" }
              }
            )
          );
        }

        // Mock the discovery endpoint
        if (url.includes("/.well-known/openid_configuration")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                issuer: "https://test.auth0.com/",
                authorization_endpoint: "https://test.auth0.com/authorize",
                token_endpoint: "https://test.auth0.com/oauth/token",
                jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
                end_session_endpoint: "https://test.auth0.com/v2/logout"
              }),
              {
                headers: { "Content-Type": "application/json" }
              }
            )
          );
        }

        return Promise.resolve(new Response("Not Found", { status: 404 }));
      })
    });

    // Mock oauth4webapi functions
    const mockDiscoveryResponse = new Response(
      JSON.stringify({
        issuer: "https://test.auth0.com/",
        authorization_endpoint: "https://test.auth0.com/authorize",
        token_endpoint: "https://test.auth0.com/oauth/token",
        jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
        end_session_endpoint: "https://test.auth0.com/v2/logout"
      }),
      {
        headers: { "Content-Type": "application/json" }
      }
    );

    const mockAuthServerMetadata = {
      issuer: "https://test.auth0.com/",
      authorization_endpoint: "https://test.auth0.com/authorize",
      token_endpoint: "https://test.auth0.com/oauth/token",
      jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
      end_session_endpoint: "https://test.auth0.com/v2/logout"
    } as oauth.AuthorizationServer;

    vi.mocked(oauth.discoveryRequest).mockResolvedValue(mockDiscoveryResponse);
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(
      mockAuthServerMetadata
    );

    // Mock PKCE and state generation functions
    vi.mocked(oauth.generateRandomState).mockReturnValue("mock-state-123");
    vi.mocked(oauth.generateRandomNonce).mockReturnValue("mock-nonce-123");
    vi.mocked(oauth.generateRandomCodeVerifier).mockReturnValue(
      "mock-code-verifier-123"
    );
    vi.mocked(oauth.calculatePKCECodeChallenge).mockResolvedValue(
      "mock-code-challenge-123"
    );

    vi.mocked(oauth.validateAuthResponse).mockReturnValue(
      new URLSearchParams("code=auth_code")
    );
    vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue(
      new Response()
    );
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      token_type: "Bearer",
      access_token: "access_token_123",
      id_token: "mock_id_token",
      refresh_token: "refresh_token_123",
      expires_in: 3600,
      scope: "openid profile email"
    } as oauth.TokenEndpointResponse);
    vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
      sub: "user123",
      nonce: "test-nonce",
      aud: "test-client-id",
      iss: "https://test.auth0.com/",
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 3600
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Happy Path", () => {
    it("should clean up all transaction cookies after successful authentication", async () => {
      // Arrange: Create a login
      const loginReq = new NextRequest("http://localhost:3000/api/auth/login");
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
      const loginReq = new NextRequest("http://localhost:3000/api/auth/login");
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
      const loginReq = new NextRequest("http://localhost:3000/api/auth/login");
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
        sessionStore,
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes: {
          login: "/api/auth/login",
          logout: "/api/auth/logout",
          callback: "/api/auth/callback"
        },
        fetch: vi.fn().mockImplementation((url) => {
          // Mock the token endpoint
          if (url.includes("/oauth/token")) {
            return Promise.resolve(
              new Response(
                JSON.stringify({
                  access_token: "access_token_123",
                  id_token:
                    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJpc3MiOiJodHRwczovL3Rlc3QuYXV0aDAuY29tLyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDA3MjAwfQ.mock_signature",
                  refresh_token: "refresh_token_123",
                  token_type: "Bearer",
                  expires_in: 3600,
                  scope: "openid profile email"
                }),
                {
                  headers: { "Content-Type": "application/json" }
                }
              )
            );
          }

          // Mock discovery endpoint
          if (url.includes("/.well-known/openid_configuration")) {
            return Promise.resolve(
              new Response(
                JSON.stringify({
                  issuer: "https://test.auth0.com/",
                  authorization_endpoint: "https://test.auth0.com/authorize",
                  token_endpoint: "https://test.auth0.com/oauth/token",
                  userinfo_endpoint: "https://test.auth0.com/userinfo",
                  jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
                  end_session_endpoint: "https://test.auth0.com/v2/logout"
                }),
                {
                  headers: { "Content-Type": "application/json" }
                }
              )
            );
          }

          // Mock the JWKS endpoint
          if (url.includes("/.well-known/jwks.json")) {
            return Promise.resolve(
              new Response(
                JSON.stringify({
                  keys: [
                    {
                      kty: "RSA",
                      kid: "test-key-id",
                      use: "sig",
                      n: "mock_n_value",
                      e: "AQAB"
                    }
                  ]
                }),
                {
                  headers: { "Content-Type": "application/json" }
                }
              )
            );
          }

          // Default mock response
          return Promise.resolve(new Response("Not Found", { status: 404 }));
        })
      });

      // Act: Create a login
      const loginReq = new NextRequest("http://localhost:3000/api/auth/login");
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
      const saveSpy = vi.spyOn(transactionStore, "save");

      // Act: Call startInteractiveLogin
      await authClient.startInteractiveLogin();

      // Assert: Verify save was called with only 2 parameters (no reqCookies)
      expect(saveSpy).toHaveBeenCalledTimes(1);
      const [resCookies, transactionState, reqCookies] = saveSpy.mock.calls[0];
      expect(resCookies).toBeDefined();
      expect(transactionState).toBeDefined();
      expect(reqCookies).toBeUndefined(); // Should be undefined for performance
    });
  });
});
