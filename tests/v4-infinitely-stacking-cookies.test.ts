import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthClient } from "../src/server/auth-client.js";

// Mock dependencies
vi.mock("../src/server/transaction-store.js");
vi.mock("../src/server/session/abstract-session-store.js");

describe("v4-infinitely-stacking-cookies - v4: Infinitely stacking cookies regression", () => {
  let authClient: AuthClient;
  let mockTransactionStore: any;
  let mockSessionStore: any;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();

    // Create mocks
    mockTransactionStore = {
      save: vi.fn(),
      get: vi.fn(),
      delete: vi.fn(),
      deleteAll: vi.fn(),
      getCookiePrefix: vi.fn().mockReturnValue("__txn_")
    };

    mockSessionStore = {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn()
    };

    // Create AuthClient instance with mocked dependencies
    authClient = new AuthClient({
      domain: "test.auth0.com",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      appBaseUrl: "http://localhost:3000",
      secret: "test-secret",
      transactionStore: mockTransactionStore,
      sessionStore: mockSessionStore
    } as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Happy Path", () => {
    it("should cleanup excess transaction cookies when starting interactive login", async () => {
      // Arrange: Mock request with multiple existing transaction cookies
      const mockCookies = {
        getAll: vi.fn().mockReturnValue([
          { name: "__txn_state1", value: "value1" },
          { name: "__txn_state2", value: "value2" },
          { name: "__txn_state3", value: "value3" },
          { name: "other_cookie", value: "other_value" }
        ])
      };

      // Mock the authorization URL generation
      vi.spyOn(authClient as any, "authorizationUrl").mockResolvedValue([
        null,
        new URL("https://test.auth0.com/authorize")
      ]);

      // Act: Start interactive login with request cookies
      await authClient.startInteractiveLogin({}, mockCookies as any);

      // Assert: Should have called delete for excess cookies (keeping threshold of 2)
      expect(mockTransactionStore.delete).toHaveBeenCalledWith(
        expect.anything(),
        "state1"
      );
      expect(mockTransactionStore.delete).toHaveBeenCalledTimes(1); // Only 1 cookie should be deleted (3 total - 2 threshold = 1)
      expect(mockTransactionStore.save).toHaveBeenCalledTimes(1);
    });

    it("should not cleanup when transaction cookies are below threshold", async () => {
      // Arrange: Mock request with only 1 existing transaction cookie
      const mockCookies = {
        getAll: vi.fn().mockReturnValue([
          { name: "__txn_state1", value: "value1" },
          { name: "other_cookie", value: "other_value" }
        ])
      };

      // Mock the authorization URL generation
      vi.spyOn(authClient as any, "authorizationUrl").mockResolvedValue([
        null,
        new URL("https://test.auth0.com/authorize")
      ]);

      // Act: Start interactive login with request cookies
      await authClient.startInteractiveLogin({}, mockCookies as any);

      // Assert: Should not have called delete (only 1 cookie, below threshold of 2)
      expect(mockTransactionStore.delete).not.toHaveBeenCalled();
      expect(mockTransactionStore.save).toHaveBeenCalledTimes(1);
    });

    it("should cleanup transaction cookie on callback error", async () => {
      // Arrange: Mock callback error scenario
      const mockRequest = new NextRequest(
        "http://localhost:3000/auth/callback?state=test-state&error=access_denied"
      );

      mockTransactionStore.get.mockResolvedValue({
        payload: {
          state: "test-state",
          returnTo: "/",
          nonce: "test-nonce",
          codeVerifier: "test-verifier",
          responseType: "code"
        }
      });

      // Mock discovery to return error
      vi.spyOn(
        authClient as any,
        "discoverAuthorizationServerMetadata"
      ).mockResolvedValue([new Error("Discovery failed"), null]);

      // Act: Handle callback with error
      const response = await authClient.handleCallback(mockRequest);

      // Assert: Should cleanup the transaction cookie on error
      expect(mockTransactionStore.delete).toHaveBeenCalledWith(
        expect.anything(),
        "test-state"
      );
      expect(response.status).toBe(500); // Default error response
    });
  });

  describe("Edge Cases", () => {
    it("should handle cleanup when no request cookies provided", async () => {
      // Arrange: Start login without request cookies
      vi.spyOn(authClient as any, "authorizationUrl").mockResolvedValue([
        null,
        new URL("https://test.auth0.com/authorize")
      ]);

      // Act: Start interactive login without request cookies
      await authClient.startInteractiveLogin({});

      // Assert: Should not attempt cleanup but should still save transaction
      expect(mockTransactionStore.delete).not.toHaveBeenCalled();
      expect(mockTransactionStore.save).toHaveBeenCalledTimes(1);
    });

    it("should extract state correctly from cookie names", async () => {
      // Arrange: Mock cookies with specific state patterns
      const mockCookies = {
        getAll: vi.fn().mockReturnValue([
          {
            name: "__txn_RaYuKTZuJbZ-10NrYwmh8sE5Eb-rClUcD3Xr25ea4Jk",
            value: "value1"
          },
          { name: "__txn_another-long-state-value", value: "value2" },
          { name: "__txn_simple", value: "value3" }
        ])
      };

      vi.spyOn(authClient as any, "authorizationUrl").mockResolvedValue([
        null,
        new URL("https://test.auth0.com/authorize")
      ]);

      // Act
      await authClient.startInteractiveLogin({}, mockCookies as any);

      // Assert: Should extract state correctly (delete oldest which is first in array)
      expect(mockTransactionStore.delete).toHaveBeenCalledWith(
        expect.anything(),
        "RaYuKTZuJbZ-10NrYwmh8sE5Eb-rClUcD3Xr25ea4Jk"
      );
    });

    it("should handle multiple error scenarios in callback", async () => {
      // Test missing state error
      const requestMissingState = new NextRequest(
        "http://localhost:3000/auth/callback"
      );

      const responseMissingState =
        await authClient.handleCallback(requestMissingState);
      expect(responseMissingState.status).toBe(500);

      // Test invalid state error (transaction not found)
      const requestInvalidState = new NextRequest(
        "http://localhost:3000/auth/callback?state=invalid-state"
      );
      mockTransactionStore.get.mockResolvedValue(null);

      const responseInvalidState =
        await authClient.handleCallback(requestInvalidState);
      expect(responseInvalidState.status).toBe(500);
      // Note: Invalid state error does NOT delete cookie as it may not exist
      // This is consistent with existing behavior and prevents double-deletion
    });
  });

  describe("Configuration Options", () => {
    describe("enableParallelTransactions option", () => {
      it("should delete all transaction cookies when enableParallelTransactions is false", async () => {
        // Create AuthClient with parallel transactions disabled
        const authClientSingleTxn = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: false
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientSingleTxn as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock request with multiple existing transaction cookies
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" }
          ])
        };

        // Call startInteractiveLogin directly to avoid network calls
        await authClientSingleTxn.startInteractiveLogin({}, mockCookies as any);

        // Verify deleteAll was called (for single transaction mode)
        expect(mockTransactionStore.deleteAll).toHaveBeenCalledTimes(1);

        // Verify save was called with custom expiration (default 3600)
        expect(mockTransactionStore.save).toHaveBeenCalledWith(
          expect.anything(),
          expect.any(Object),
          3600
        );
      });

      it("should use threshold-based cleanup when enableParallelTransactions is true", async () => {
        // Create AuthClient with parallel transactions enabled (default)
        const authClientParallelTxn = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: true,
          maxTxnCookieCount: 2
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientParallelTxn as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock 4 existing transaction cookies (above threshold of 2)
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" },
            { name: "__txn_state4", value: "txn4" }
          ])
        };

        // Call startInteractiveLogin directly to avoid network calls
        await authClientParallelTxn.startInteractiveLogin(
          {},
          mockCookies as any
        );

        // Verify deleteAll was NOT called
        expect(mockTransactionStore.deleteAll).not.toHaveBeenCalled();

        // Verify individual delete was called for excess cookies (4 - 2 = 2 deletes)
        expect(mockTransactionStore.delete).toHaveBeenCalledTimes(2);
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state1"
        );
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state2"
        );
      });
    });

    describe("txnCookieExpiration option", () => {
      it("should use custom expiration when provided", async () => {
        const customExpiration = 7200; // 2 hours

        const authClientCustomExp = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          txnCookieExpiration: customExpiration
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientCustomExp as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        const mockCookies = {
          getAll: vi.fn().mockReturnValue([])
        };

        await authClientCustomExp.startInteractiveLogin({}, mockCookies as any);

        // Verify save was called with custom expiration
        expect(mockTransactionStore.save).toHaveBeenCalledWith(
          expect.anything(),
          expect.any(Object),
          customExpiration
        );
      });

      it("should use default expiration (3600) when not provided", async () => {
        const authClientDefaultExp = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore
          // txnCookieExpiration not provided
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientDefaultExp as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        const mockCookies = {
          getAll: vi.fn().mockReturnValue([])
        };

        await authClientDefaultExp.startInteractiveLogin(
          {},
          mockCookies as any
        );

        // Verify save was called with default expiration
        expect(mockTransactionStore.save).toHaveBeenCalledWith(
          expect.anything(),
          expect.any(Object),
          3600
        );
      });
    });

    describe("maxTxnCookieCount option", () => {
      it("should use custom maxTxnCookieCount for cleanup threshold", async () => {
        const customMaxCount = 5;

        const authClientCustomMax = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: true,
          maxTxnCookieCount: customMaxCount
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientCustomMax as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock 7 existing transaction cookies (above threshold of 5)
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" },
            { name: "__txn_state4", value: "txn4" },
            { name: "__txn_state5", value: "txn5" },
            { name: "__txn_state6", value: "txn6" },
            { name: "__txn_state7", value: "txn7" }
          ])
        };

        await authClientCustomMax.startInteractiveLogin({}, mockCookies as any);

        // Verify delete was called for excess cookies (7 - 5 = 2 deletes)
        expect(mockTransactionStore.delete).toHaveBeenCalledTimes(2);
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state1"
        );
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state2"
        );
      });

      it("should use default maxTxnCookieCount (2) when not provided", async () => {
        const authClientDefaultMax = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: true
          // maxTxnCookieCount not provided (default should be 2)
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientDefaultMax as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock 4 existing transaction cookies (above default threshold of 2)
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" },
            { name: "__txn_state4", value: "txn4" }
          ])
        };

        await authClientDefaultMax.startInteractiveLogin(
          {},
          mockCookies as any
        );

        // Verify delete was called for excess cookies (4 - 2 = 2 deletes)
        expect(mockTransactionStore.delete).toHaveBeenCalledTimes(2);
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state1"
        );
        expect(mockTransactionStore.delete).toHaveBeenCalledWith(
          expect.anything(),
          "state2"
        );
      });

      it("should not cleanup when transaction count is below threshold", async () => {
        const authClientBelowThreshold = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: true,
          maxTxnCookieCount: 5
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientBelowThreshold as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock 3 existing transaction cookies (below threshold of 5)
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" }
          ])
        };

        await authClientBelowThreshold.startInteractiveLogin(
          {},
          mockCookies as any
        );

        // Verify no cleanup occurred
        expect(mockTransactionStore.delete).not.toHaveBeenCalled();
        expect(mockTransactionStore.deleteAll).not.toHaveBeenCalled();
      });
    });

    describe("Combined options behavior", () => {
      it("should respect all configuration options together", async () => {
        const authClientCombined = new AuthClient({
          domain: "test.auth0.com",
          clientId: "test-client-id",
          clientSecret: "test-client-secret",
          appBaseUrl: "http://localhost:3000",
          secret: "test-secret",
          transactionStore: mockTransactionStore,
          sessionStore: mockSessionStore,
          enableParallelTransactions: true,
          txnCookieExpiration: 1800, // 30 minutes
          maxTxnCookieCount: 3
        } as any);

        // Mock the authorization URL generation
        vi.spyOn(
          authClientCombined as any,
          "authorizationUrl"
        ).mockResolvedValue([
          null,
          new URL("https://test.auth0.com/authorize")
        ]);

        // Mock 5 existing transaction cookies (above threshold of 3)
        const mockCookies = {
          getAll: vi.fn().mockReturnValue([
            { name: "__txn_state1", value: "txn1" },
            { name: "__txn_state2", value: "txn2" },
            { name: "__txn_state3", value: "txn3" },
            { name: "__txn_state4", value: "txn4" },
            { name: "__txn_state5", value: "txn5" }
          ])
        };

        await authClientCombined.startInteractiveLogin({}, mockCookies as any);

        // Verify cleanup used custom threshold (5 - 3 = 2 deletes)
        expect(mockTransactionStore.delete).toHaveBeenCalledTimes(2);

        // Verify save used custom expiration
        expect(mockTransactionStore.save).toHaveBeenCalledWith(
          expect.anything(),
          expect.any(Object),
          1800
        );

        // Verify deleteAll was not called (parallel transactions enabled)
        expect(mockTransactionStore.deleteAll).not.toHaveBeenCalled();
      });
    });
  });
});
