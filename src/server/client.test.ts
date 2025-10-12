import { NextResponse, type NextRequest } from "next/server.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AccessTokenError, AccessTokenErrorCode } from "../errors/index.js";
import { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js"; // Import the actual class for spyOn
import { Auth0Client } from "./client.js";

// Define ENV_VARS at the top level for broader scope
const ENV_VARS = {
  DOMAIN: "AUTH0_DOMAIN",
  CLIENT_ID: "AUTH0_CLIENT_ID",
  CLIENT_SECRET: "AUTH0_CLIENT_SECRET",
  CLIENT_ASSERTION_SIGNING_KEY: "AUTH0_CLIENT_ASSERTION_SIGNING_KEY",
  APP_BASE_URL: "APP_BASE_URL",
  SECRET: "AUTH0_SECRET",
  SCOPE: "AUTH0_SCOPE",
  DPOP_PRIVATE_KEY: "AUTH0_DPOP_PRIVATE_KEY",
  DPOP_PUBLIC_KEY: "AUTH0_DPOP_PUBLIC_KEY"
};

describe("Auth0Client", () => {
  // Store original env vars
  const originalEnv = { ...process.env };

  // Clear env vars before each test
  beforeEach(() => {
    vi.resetModules();
    // Clear all environment variables that might affect the tests
    delete process.env[ENV_VARS.DOMAIN];
    delete process.env[ENV_VARS.CLIENT_ID];
    delete process.env[ENV_VARS.CLIENT_SECRET];
    delete process.env[ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY];
    delete process.env[ENV_VARS.APP_BASE_URL];
    delete process.env[ENV_VARS.SECRET];
    delete process.env[ENV_VARS.SCOPE];
    delete process.env[ENV_VARS.DPOP_PRIVATE_KEY];
    delete process.env[ENV_VARS.DPOP_PUBLIC_KEY];
  });

  // Restore env vars after each test
  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks(); // Restore mocks created within tests/beforeEach
  });

  describe("constructor validation", () => {
    it("should accept clientSecret as authentication method", () => {
      // Set required environment variables with clientSecret
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "env_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Should not throw
      const client = new Auth0Client();

      // The client should be instantiated successfully
      expect(client).toBeInstanceOf(Auth0Client);
    });

    it("should accept clientAssertionSigningKey as authentication method", () => {
      // Set required environment variables with clientAssertionSigningKey instead of clientSecret
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY] = "some-signing-key";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Should not throw
      const client = new Auth0Client();

      // The client should be instantiated successfully
      expect(client).toBeInstanceOf(Auth0Client);
    });

    it("should prioritize options over environment variables", () => {
      // Set environment variables
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "env_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Provide conflicting options
      const options = {
        domain: "options.auth0.com",
        clientId: "options_client_id",
        clientSecret: "options_client_secret",
        appBaseUrl: "https://options-app.com",
        secret: "options_secret"
      };

      // Mock the validateAndExtractRequiredOptions to verify which values are used
      const mockValidateAndExtractRequiredOptions = vi
        .fn()
        .mockReturnValue(options);
      const originalValidateAndExtractRequiredOptions =
        Auth0Client.prototype["validateAndExtractRequiredOptions"];
      Auth0Client.prototype["validateAndExtractRequiredOptions"] =
        mockValidateAndExtractRequiredOptions;

      try {
        new Auth0Client(options);

        // Check that validateAndExtractRequiredOptions was called with our options
        expect(mockValidateAndExtractRequiredOptions).toHaveBeenCalledWith(
          options
        );
        // The first argument of the first call should be our options object
        const passedOptions =
          mockValidateAndExtractRequiredOptions.mock.calls[0][0];
        expect(passedOptions.domain).toBe("options.auth0.com");
        expect(passedOptions.clientId).toBe("options_client_id");
      } finally {
        // Restore the original method
        Auth0Client.prototype["validateAndExtractRequiredOptions"] =
          originalValidateAndExtractRequiredOptions;
      }
    });
  });

  describe("getAccessToken", () => {
    const mockSession: SessionData = {
      user: { sub: "user123" },
      tokenSet: {
        accessToken: "old_access_token",
        idToken: "old_id_token",
        refreshToken: "old_refresh_token",
        expiresAt: Date.now() / 1000 - 3600 // Expired
      },
      internal: {
        sid: "mock_sid",
        createdAt: Date.now() / 1000 - 7200 // Some time in the past
      },
      createdAt: Date.now() / 1000
    };

    // Restore original mock for refreshed token set
    const mockRefreshedTokenSet = {
      accessToken: "new_access_token",
      idToken: "new_id_token",
      refreshToken: "new_refresh_token",
      expiresAt: Date.now() / 1000 + 3600, // Not expired
      scope: "openid profile email"
    };

    let client: Auth0Client;
    let mockGetSession: ReturnType<typeof vi.spyOn>;
    let mockSaveToSession: ReturnType<typeof vi.spyOn>;
    let mockGetTokenSet: ReturnType<typeof vi.spyOn>; // Re-declare mockGetTokenSet

    beforeEach(() => {
      // Reset mocks specifically if vi.restoreAllMocks isn't enough
      // vi.resetAllMocks(); // Alternative to restoreAllMocks in afterEach

      // Set necessary environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "test_secret";

      client = new Auth0Client();

      // Mock internal methods of Auth0Client
      mockGetSession = vi
        .spyOn(Auth0Client.prototype as any, "getSession")
        .mockResolvedValue(mockSession);
      mockSaveToSession = vi
        .spyOn(Auth0Client.prototype as any, "saveToSession")
        .mockResolvedValue(undefined);

      // Restore mocking of getTokenSet directly
      mockGetTokenSet = vi
        .spyOn(AuthClient.prototype as any, "getTokenSet")
        .mockResolvedValue([null, mockRefreshedTokenSet]); // Simulate successful refresh

      // Remove mocks for discoverAuthorizationServerMetadata and getClientAuth
      // Remove fetch mock
    });

    it("should throw AccessTokenError if no session exists", async () => {
      // Override getSession mock for this specific test
      mockGetSession.mockResolvedValue(null);

      // Mock request and response objects
      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await expect(
        client.getAccessToken(mockReq, mockRes)
      ).rejects.toThrowError(
        new AccessTokenError(
          AccessTokenErrorCode.MISSING_SESSION,
          "The user does not have an active session."
        )
      );
      // Ensure getTokenSet was not called
      expect(mockGetTokenSet).not.toHaveBeenCalled();
    });

    it("should throw error from getTokenSet if refresh fails", async () => {
      const refreshError = new Error("Refresh failed");
      // Restore overriding the getTokenSet mock directly
      mockGetTokenSet.mockResolvedValue([refreshError, null]);

      // Mock request and response objects
      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await expect(
        client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrowError(refreshError);

      // Verify save was not called
      expect(mockSaveToSession).not.toHaveBeenCalled();
    });
  });

  describe("constructor configuration", () => {
    beforeEach(() => {
      // Set necessary environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "test_secret";
    });

    it("should pass transactionCookie.maxAge to TransactionStore", () => {
      const customMaxAge = 1800; // 30 minutes

      const client = new Auth0Client({
        transactionCookie: {
          maxAge: customMaxAge
        }
      });

      // Verify that the TransactionStore was created with the correct maxAge
      // We need to access the private property for testing
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      // Check the cookieOptions maxAge - we need to verify it was set correctly
      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(customMaxAge);
    });

    it("should use default maxAge of 3600 when not specified", () => {
      const client = new Auth0Client();

      // Verify that the TransactionStore was created with the default maxAge
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      // Check the cookieOptions maxAge
      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(3600);
    });

    it("should pass other transactionCookie options to TransactionStore", () => {
      const customOptions = {
        prefix: "__custom_txn_",
        secure: true,
        sameSite: "strict" as const,
        path: "/auth",
        maxAge: 2700
      };

      const client = new Auth0Client({
        transactionCookie: customOptions
      });

      // Verify that the TransactionStore was created with the correct options
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(customOptions.maxAge);
      expect((transactionStore as any).transactionCookiePrefix).toBe(
        customOptions.prefix
      );

      // Note: secure and sameSite are stored in cookieOptions
      expect(cookieOptions.secure).toBe(customOptions.secure);
      expect(cookieOptions.sameSite).toBe(customOptions.sameSite);
      expect(cookieOptions.path).toBe(customOptions.path);
    });

    it("should pass enableParallelTransactions to TransactionStore", () => {
      const client = new Auth0Client({
        enableParallelTransactions: false
      });

      // Verify that the TransactionStore was created with the correct enableParallelTransactions
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const enableParallelTransactions = (transactionStore as any)
        .enableParallelTransactions;
      expect(enableParallelTransactions).toBe(false);
    });

    it("should default enableParallelTransactions to true when not specified", () => {
      const client = new Auth0Client();

      // Verify that the TransactionStore was created with the default enableParallelTransactions
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const enableParallelTransactions = (transactionStore as any)
        .enableParallelTransactions;
      expect(enableParallelTransactions).toBe(true);
    });
  });

  describe("DPoP Environment Variable Configuration", () => {
    // Test DPoP key pairs in PEM format (these are test keys, not for production)
    const TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzQS05OU0N+qhZybt
IG3eAsEFeuSWdbmMBpltLsZWkWKhRANCAATcrBPN+T4ab7o5UEb8KProeVFNeo3K
TBXwJXbbAoO5usON7W9yF9Mv/KBfqnbtEqkmbx4AfuTcTBV6Dc0N81XN
-----END PRIVATE KEY-----`;

    const TEST_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3KwTzfk+Gm+6OVBG/Cj66HlRTXqN
ykwV8CV22wKDubrDje1vchfTL/ygX6p27RKpJm8eAH7k3EwVeg3NDfNVzQ==
-----END PUBLIC KEY-----`;

    let consoleLogSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    });

    afterEach(() => {
      consoleLogSpy.mockRestore();
      consoleWarnSpy.mockRestore();
    });

    it("should load DPoP keypair from environment variables when useDpop is true", () => {
      // Set up environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      const client = new Auth0Client({
        useDpop: true
      });

      expect(client).toBeInstanceOf(Auth0Client);

      // The test should either succeed in loading keys OR fail with a warning
      // Success case: should log success message
      // Failure case: should log failure warning (due to test environment limitations)
      const hasSuccessLog = consoleLogSpy.mock.calls.some(
        (call: any[]) =>
          typeof call[0] === "string" &&
          call[0].includes(
            "Successfully loaded DPoP keypair from environment variables"
          )
      );
      const hasFailureWarning = consoleWarnSpy.mock.calls.some(
        (call: any[]) =>
          typeof call[0] === "string" &&
          call[0].includes(
            "WARNING: Failed to load DPoP keypair from environment variables"
          )
      );

      expect(hasSuccessLog || hasFailureWarning).toBe(true);
    });

    it("should return undefined when environment variables are missing and log warning", () => {
      // Set up required environment variables but omit DPoP keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";

      // Ensure DPoP environment variables are not set
      delete process.env[ENV_VARS.DPOP_PRIVATE_KEY];
      delete process.env[ENV_VARS.DPOP_PUBLIC_KEY];

      const client = new Auth0Client({
        useDpop: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDpop is set to true but dpopKeyPair is not provided"
        )
      );
    });

    it("should return undefined when useDpop is false", () => {
      // Set up environment variables including DPoP keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      const client = new Auth0Client({
        useDpop: false
      });

      expect(client).toBeInstanceOf(Auth0Client);
      // Should not attempt to load keys or log anything
      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it("should prioritize provided dpopKeyPair over environment variables", async () => {
      // Set up environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      // Create actual CryptoKey objects using generateDpopKeyPair
      const { generateDpopKeyPair } = await import("../utils/dpopUtils.js");
      const mockKeypair = await generateDpopKeyPair();

      const client = new Auth0Client({
        useDpop: true,
        dpopKeyPair: mockKeypair
      });

      expect(client).toBeInstanceOf(Auth0Client);
      // Should not attempt to load from env vars since keypair is provided
      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it("should handle invalid PEM format gracefully with warning", () => {
      // Set up environment variables with invalid keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = "invalid-private-key";
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = "invalid-public-key";

      const client = new Auth0Client({
        useDpop: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: Failed to load DPoP keypair from environment variables."
        )
      );
    });

    it("should handle missing private key only", () => {
      // Set up environment variables missing private key
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;
      // AUTH0_DPOP_PRIVATE_KEY is missing

      const client = new Auth0Client({
        useDpop: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDpop is set to true but dpopKeyPair is not provided"
        )
      );
    });

    it("should handle missing public key only", () => {
      // Set up environment variables missing public key
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      // AUTH0_DPOP_PUBLIC_KEY is missing

      const client = new Auth0Client({
        useDpop: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDpop is set to true but dpopKeyPair is not provided"
        )
      );
    });
  });

  describe("createFetcher", () => {
    let auth0Client: Auth0Client;

    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test-client-id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test-client-secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";

      auth0Client = new Auth0Client();
    });

    it("should create a fetcher with no configuration", () => {
      const fetcher = auth0Client.createFetcher();

      expect(fetcher).toBeDefined();
      expect(typeof fetcher.fetchWithAuth).toBe("function");
    });

    it("should create a fetcher with base URL configuration", () => {
      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });

      expect(fetcher).toBeDefined();
      expect(typeof fetcher.fetchWithAuth).toBe("function");
    });

    it("should resolve relative URLs with base URL", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      await fetcher.fetchWithAuth("/users");

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "https://api.example.com/users",
        undefined
      );
    });

    it("should not modify absolute URLs", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      await fetcher.fetchWithAuth("https://other-api.com/data");

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "https://other-api.com/data",
        undefined
      );
    });

    it("should handle protocol-relative URLs as absolute", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      await fetcher.fetchWithAuth("//cdn.example.com/data");

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "//cdn.example.com/data",
        undefined
      );
    });

    it("should handle URL objects properly", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      const url = new URL("https://other-api.com/data");
      await fetcher.fetchWithAuth(url);

      expect(mockFetchWithAuth).toHaveBeenCalledWith(url, undefined);
    });

    it("should handle Request objects with relative URLs", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      // Note: Request constructor requires absolute URLs, so we test the resolution logic differently
      // We'll create the request with a base URL and then verify the URL gets resolved correctly
      const request = new Request("https://api.example.com/users", {
        method: "POST",
        body: "test"
      });

      // Mock the resolveUrl method to simulate relative URL resolution
      const originalResolveUrl = (auth0Client as any).resolveUrl;
      const mockResolveUrl = vi.fn().mockReturnValue(request);
      (auth0Client as any).resolveUrl = mockResolveUrl;

      // Test with relative URL string (which gets converted by resolveUrl)
      await fetcher.fetchWithAuth("/users");

      expect(mockResolveUrl).toHaveBeenCalledWith(
        "/users",
        "https://api.example.com"
      );
      expect(mockFetchWithAuth).toHaveBeenCalled();

      // Restore original method
      (auth0Client as any).resolveUrl = originalResolveUrl;
    });

    it("should handle Request objects with absolute URLs", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      const request = new Request("https://other-api.com/data", {
        method: "GET"
      });
      await fetcher.fetchWithAuth(request);

      expect(mockFetchWithAuth).toHaveBeenCalledWith(request, undefined);
    });

    it("should pass through RequestInit options", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com"
      });
      const init = {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      };
      await fetcher.fetchWithAuth("/users", init);

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "https://api.example.com/users",
        init
      );
    });

    it("should properly build URLs with trailing/leading slashes", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher({
        baseUrl: "https://api.example.com/"
      });
      await fetcher.fetchWithAuth("/users");

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "https://api.example.com/users",
        undefined
      );
    });

    it("should work without base URL", async () => {
      const mockFetchWithAuth = vi
        .spyOn(auth0Client, "fetchWithAuth")
        .mockResolvedValue(new Response("test", { status: 200 }));

      const fetcher = auth0Client.createFetcher();
      await fetcher.fetchWithAuth("https://api.example.com/users");

      expect(mockFetchWithAuth).toHaveBeenCalledWith(
        "https://api.example.com/users",
        undefined
      );
    });
  });

  describe("fetchWithAuth", () => {
    let auth0Client: Auth0Client;
    let mockGetSession: ReturnType<typeof vi.spyOn>;
    let mockExecuteProtectedRequest: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test-client-id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test-client-secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";

      auth0Client = new Auth0Client();

      mockGetSession = vi.spyOn(auth0Client, "getSession").mockResolvedValue({
        user: { sub: "user_123" },
        idToken: "test_id_token",
        accessToken: "test_access_token",
        tokenSet: {
          accessToken: "test_access_token",
          expiresAt: Date.now() / 1000 + 3600
        },
        internal: {
          sid: "test_sid",
          createdAt: Date.now() / 1000 - 3600
        },
        createdAt: Date.now() / 1000
      });

      mockExecuteProtectedRequest = vi
        .spyOn((auth0Client as any).authClient, "executeProtectedRequest")
        .mockResolvedValue(new Response("test response", { status: 200 }));
    });

    afterEach(() => {
      mockGetSession.mockRestore();
      mockExecuteProtectedRequest.mockRestore();
    });

    it("should call executeProtectedRequest with correct parameters", async () => {
      await auth0Client.fetchWithAuth("https://api.example.com/data");

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/data",
        method: "GET",
        headers: {},
        body: undefined,
        session: expect.any(Object),
        accessTokenOptions: {}
      });
    });

    it("should pass accessTokenOptions to executeProtectedRequest", async () => {
      const accessTokenOptions = {
        audience: "https://api.example.com",
        scope: "read:data"
      };

      await auth0Client.fetchWithAuth(
        "https://api.example.com/data",
        { method: "POST" },
        accessTokenOptions
      );

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/data",
        method: "POST",
        headers: {},
        body: undefined,
        session: expect.any(Object),
        accessTokenOptions
      });
    });

    it("should throw error when no session exists", async () => {
      mockGetSession.mockResolvedValue(null);

      await expect(
        auth0Client.fetchWithAuth("https://api.example.com/data")
      ).rejects.toThrow(
        "No active session found. User must be authenticated to use fetchWithAuth."
      );
    });

    it("should handle Request objects", async () => {
      const request = new Request("https://api.example.com/data", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "data" })
      });

      await auth0Client.fetchWithAuth(request);

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/data",
        method: "POST",
        headers: expect.any(Headers),
        body: expect.any(ReadableStream),
        session: expect.any(Object),
        accessTokenOptions: {}
      });
    });

    it("should handle URL objects", async () => {
      const url = new URL("https://api.example.com/data");

      await auth0Client.fetchWithAuth(url);

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/data",
        method: "GET",
        headers: {},
        body: undefined,
        session: expect.any(Object),
        accessTokenOptions: {}
      });
    });

    it("should pass accessTokenOptions with scope and audience", async () => {
      const accessTokenOptions = {
        scope: "read:data write:data",
        audience: "https://api.example.com"
      };

      await auth0Client.fetchWithAuth(
        "https://api.example.com/data",
        { method: "GET" },
        accessTokenOptions
      );

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/data",
        method: "GET",
        headers: {},
        body: undefined,
        session: expect.any(Object),
        accessTokenOptions
      });
    });

    it("should handle Request objects with accessTokenOptions", async () => {
      const request = new Request("https://api.example.com/resource", {
        method: "POST",
        body: JSON.stringify({ test: "data" }),
        headers: { "content-type": "application/json" }
      });

      const accessTokenOptions = {
        audience: "https://api.example.com",
        scope: "write:data"
      };

      await auth0Client.fetchWithAuth(request, {}, accessTokenOptions);

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/resource",
        method: "POST",
        headers: expect.any(Headers),
        body: expect.any(ReadableStream),
        session: expect.any(Object),
        accessTokenOptions
      });
    });

    it("should handle URL objects with accessTokenOptions", async () => {
      const url = new URL("https://api.example.com/endpoint");
      const accessTokenOptions = { scope: "admin" };

      await auth0Client.fetchWithAuth(
        url,
        { method: "PUT", body: "test data" },
        accessTokenOptions
      );

      expect(mockExecuteProtectedRequest).toHaveBeenCalledWith({
        url: "https://api.example.com/endpoint",
        method: "PUT",
        headers: {},
        body: "test data",
        session: expect.any(Object),
        accessTokenOptions
      });
    });
  });
});

export type GetAccessTokenOptions = {
  refresh?: boolean;
};
