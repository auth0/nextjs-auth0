import * as oauth from "oauth4webapi";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { AuthClient } from "./auth-client.js";
import { Fetcher } from "./fetcher.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Mock oauth4webapi
vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    protectedResourceRequest: vi.fn(),
    isDPoPNonceError: vi.fn(),
    DPoP: vi.fn()
  };
});

describe("Fetcher", () => {
  let fetcher: Fetcher<Response>;
  let mockFetch: any;
  let authClient: AuthClient;
  let hooks: {
    getAccessToken: ReturnType<typeof vi.fn>;
    isDpopEnabled: ReturnType<typeof vi.fn>;
  };
  let secret: string;

  const DEFAULT = {
    domain: "test.auth0.com",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    appBaseUrl: "https://example.com"
  };

  beforeEach(async () => {
    secret = await generateSecret(32);
    mockFetch = vi.fn().mockResolvedValue(new Response("OK"));

    // Mock oauth functions
    (oauth.protectedResourceRequest as any).mockResolvedValue(
      new Response("OK")
    );
    (oauth.DPoP as any).mockResolvedValue({
      privateKey: "test-key",
      publicKey: "test-public-key"
    });
    (oauth.isDPoPNonceError as any).mockReturnValue(false);

    // Create a basic authClient
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });

    authClient = new AuthClient({
      transactionStore,
      sessionStore,
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      secret,
      appBaseUrl: DEFAULT.appBaseUrl,
      routes: getDefaultRoutes()
    });

    const config = {
      authClient,
      baseUrl: "https://api.example.com",
      fetch: mockFetch,
      httpOptions: () => ({})
    };

    hooks = {
      getAccessToken: vi.fn().mockResolvedValue("test-token"),
      isDpopEnabled: vi.fn().mockReturnValue(false)
    };

    fetcher = new Fetcher(config, hooks);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("basic functionality", () => {
    it("should make authenticated requests using oauth.protectedResourceRequest", async () => {
      await fetcher.fetchWithAuth("https://api.example.com/data");

      // Verify that protectedResourceRequest was called - the core DPoP functionality
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      // Check the first few critical parameters
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[0]).toBe("test-token"); // access token
      expect(callArgs[1]).toBe("GET"); // method
      expect(callArgs[2].href).toBe("https://api.example.com/data"); // url as URL object
    });

    it("should handle POST requests", async () => {
      const requestInit: RequestInit = {
        method: "POST",
        body: JSON.stringify({ test: "data" })
      };

      await fetcher.fetchWithAuth("https://api.example.com/data", requestInit);

      expect(oauth.protectedResourceRequest).toHaveBeenCalledWith(
        expect.any(String), // access token
        "POST", // method
        expect.anything(), // url
        expect.anything(), // headers
        expect.anything(), // body
        expect.anything() // options
      );
    });

    it("should handle relative URLs", async () => {
      await fetcher.fetchWithAuth("/users");

      // Verify the relative URL is resolved correctly
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[0]).toBe("test-token"); // access token
      expect(callArgs[1]).toBe("GET"); // method
      expect(callArgs[2].href).toBe("https://api.example.com/users"); // url resolved as URL object
    });
  });

  describe("DPoP functionality", () => {
    it("should use DPoP when enabled", async () => {
      // Create authClient with DPoP enabled
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      const dpopAuthClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        useDPoP: true
      });

      const configWithDpop = {
        authClient: dpopAuthClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({})
      };

      const hooks = {
        getAccessToken: vi.fn().mockResolvedValue("test-token"),
        isDpopEnabled: vi.fn().mockReturnValue(true)
      };

      const dpopFetcher = new Fetcher(configWithDpop, hooks);
      await dpopFetcher.fetchWithAuth("https://api.example.com/data");

      expect(oauth.protectedResourceRequest).toHaveBeenCalled();
    });

    it("should work without DPoP when disabled", async () => {
      await fetcher.fetchWithAuth("https://api.example.com/data");

      expect(oauth.protectedResourceRequest).toHaveBeenCalled();
    });
  });

  describe("parameter disambiguation", () => {
    it("should handle fetchWithAuth(url, getAccessTokenOptions) - 2 argument form", async () => {
      const getAccessTokenOptions = {
        refresh: true,
        scope: "read:data"
      };

      await fetcher.fetchWithAuth(
        "https://api.example.com/data",
        getAccessTokenOptions
      );

      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[1]).toBe("GET"); // should default to GET when no RequestInit provided
    });

    it("should handle fetchWithAuth(url, requestInit) - 2 argument form", async () => {
      const requestInit: RequestInit = {
        method: "PUT",
        headers: { "Content-Type": "application/json" }
      };

      await fetcher.fetchWithAuth("https://api.example.com/data", requestInit);

      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[1]).toBe("PUT"); // should use method from RequestInit
    });

    it("should handle fetchWithAuth(url, requestInit, getAccessTokenOptions) - 3 argument form", async () => {
      const requestInit: RequestInit = { method: "PATCH" };
      const getAccessTokenOptions = { scope: "write:data" };

      await fetcher.fetchWithAuth(
        "https://api.example.com/data",
        requestInit,
        getAccessTokenOptions
      );

      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[1]).toBe("PATCH");
    });

    it("should treat refreshBuffer-only options as getAccessTokenOptions", async () => {
      const getAccessTokenOptions = { refreshBuffer: 45 };

      await fetcher.fetchWithAuth(
        "https://api.example.com/data",
        getAccessTokenOptions
      );

      expect(hooks.getAccessToken).toHaveBeenCalledWith(getAccessTokenOptions);
    });
  });

  describe("DPoP nonce error retry", () => {
    it("should retry on DPoP nonce error", async () => {
      // Mock isDPoPNonceError to return true for first call, false for retry
      let callCount = 0;
      (oauth.isDPoPNonceError as any).mockImplementation(() => {
        callCount++;
        return callCount === 1; // Return true only for first call
      });

      // Mock protectedResourceRequest to fail first, succeed on retry
      (oauth.protectedResourceRequest as any)
        .mockRejectedValueOnce(new Error("DPoP nonce error"))
        .mockResolvedValueOnce(new Response("OK"));

      const result = await fetcher.fetchWithAuth(
        "https://api.example.com/data"
      );

      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(2);
      expect(result).toBeInstanceOf(Response);
    });

    it("should respect retry configuration with custom delay", async () => {
      const customRetryConfig = {
        delay: 50,
        jitter: false
      };

      const configWithRetry = {
        authClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({}),
        retryConfig: customRetryConfig
      };

      const retryFetcher = new Fetcher(configWithRetry, {
        getAccessToken: vi.fn().mockResolvedValue("test-token"),
        isDpopEnabled: vi.fn().mockReturnValue(false)
      });

      // Mock DPoP nonce error
      let callCount = 0;
      (oauth.isDPoPNonceError as any).mockImplementation(() => {
        callCount++;
        return callCount === 1;
      });

      (oauth.protectedResourceRequest as any)
        .mockRejectedValueOnce(new Error("DPoP nonce error"))
        .mockResolvedValueOnce(new Response("OK"));

      const startTime = Date.now();
      await retryFetcher.fetchWithAuth("https://api.example.com/data");
      const endTime = Date.now();

      // Should have taken at least the delay time (accounting for test timing variance)
      expect(endTime - startTime).toBeGreaterThanOrEqual(40);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(2);
    });

    it("should not retry twice on DPoP nonce error", async () => {
      // Mock to always return true for isDPoPNonceError
      (oauth.isDPoPNonceError as any).mockReturnValue(true);
      (oauth.protectedResourceRequest as any).mockRejectedValue(
        new Error("DPoP nonce error")
      );

      await expect(
        fetcher.fetchWithAuth("https://api.example.com/data")
      ).rejects.toThrow("DPoP nonce error");

      // Should be called exactly twice - original + one retry
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(2);
    });
  });

  describe("URL handling", () => {
    it("should handle URL objects", async () => {
      const url = new URL("https://api.example.com/data");
      await fetcher.fetchWithAuth(url);

      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[2].href).toBe("https://api.example.com/data");
    });

    it("should throw error for relative URL without baseUrl", async () => {
      const configWithoutBase = {
        authClient,
        fetch: mockFetch,
        httpOptions: () => ({})
        // No baseUrl
      };

      const noBaseFetcher = new Fetcher(configWithoutBase, {
        getAccessToken: vi.fn().mockResolvedValue("test-token"),
        isDpopEnabled: vi.fn().mockReturnValue(false)
      });

      await expect(
        noBaseFetcher.fetchWithAuth("/relative-path")
      ).rejects.toThrow("Failed to parse URL from /relative-path");
    });

    it("should handle Request objects as input", async () => {
      const request = new Request("https://api.example.com/data", {
        method: "POST",
        body: "test data"
      });

      await fetcher.fetchWithAuth(request);

      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[1]).toBe("GET"); // Default method used by fetcher
      expect(callArgs[2].href).toBe("https://api.example.com/data"); // URL from Request
    });
  });

  describe("DPoP handle integration", () => {
    it("should pass DPoP handle to protectedResourceRequest when available", async () => {
      const mockDpopHandle = {
        privateKey: "test",
        publicKey: "test",
        calculateThumbprint: vi.fn().mockResolvedValue("thumbprint")
      };

      const configWithDpopHandle = {
        authClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({}),
        dpopHandle: mockDpopHandle
      };

      const dpopFetcher = new Fetcher(configWithDpopHandle, {
        getAccessToken: vi.fn().mockResolvedValue("test-token"),
        isDpopEnabled: vi.fn().mockReturnValue(true)
      });

      await dpopFetcher.fetchWithAuth("https://api.example.com/data");

      // Verify that DPoP handle was passed in options
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      const options = callArgs[5]; // 6th parameter is options
      expect(options.DPoP).toBe(mockDpopHandle);
    });

    it("should pass allowInsecureRequests when configured", async () => {
      const configWithInsecure = {
        authClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({}),
        allowInsecureRequests: true
      };

      const insecureFetcher = new Fetcher(configWithInsecure, {
        getAccessToken: vi.fn().mockResolvedValue("test-token"),
        isDpopEnabled: vi.fn().mockReturnValue(false)
      });

      await insecureFetcher.fetchWithAuth("https://api.example.com/data");

      // Verify protectedResourceRequest was called with correct parameters
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[0]).toBe("test-token"); // access token
      expect(callArgs[1]).toBe("GET"); // method
      expect(callArgs[2].href).toBe("https://api.example.com/data"); // URL
      expect(callArgs[3]).toBeInstanceOf(Headers); // headers
      expect(callArgs[4]).toBeNull(); // DPoP handle
      expect(typeof callArgs[5]).toBe("object"); // options
    });
  });

  describe("access token sources", () => {
    it("should use config.getAccessToken when available", async () => {
      const configAccessToken = vi.fn().mockResolvedValue("config-token");

      const configWithAccessToken = {
        authClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({}),
        getAccessToken: configAccessToken
      };

      const configTokenFetcher = new Fetcher(configWithAccessToken, {
        getAccessToken: vi.fn().mockResolvedValue("hooks-token"),
        isDpopEnabled: vi.fn().mockReturnValue(false)
      });

      await configTokenFetcher.fetchWithAuth("https://api.example.com/data");

      expect(configAccessToken).toHaveBeenCalled();
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      expect(callArgs[0]).toBe("config-token"); // Should use config token, not hooks token
    });
  });

  describe("error handling", () => {
    it("should handle oauth errors", async () => {
      (oauth.protectedResourceRequest as any).mockRejectedValue(
        new Error("OAuth error")
      );

      await expect(
        fetcher.fetchWithAuth("https://api.example.com/data")
      ).rejects.toThrow("OAuth error");
    });

    it("should handle access token errors", async () => {
      const hooks = {
        getAccessToken: vi.fn().mockRejectedValue(new Error("Token error")),
        isDpopEnabled: vi.fn().mockReturnValue(false)
      };

      const config = {
        authClient,
        baseUrl: "https://api.example.com",
        fetch: mockFetch,
        httpOptions: () => ({})
      };

      const errorFetcher = new Fetcher(config, hooks);

      await expect(
        errorFetcher.fetchWithAuth("https://api.example.com/data")
      ).rejects.toThrow("Token error");
    });
  });
});
