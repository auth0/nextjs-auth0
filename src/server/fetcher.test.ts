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

    const hooks = {
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
        useDpop: true
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
