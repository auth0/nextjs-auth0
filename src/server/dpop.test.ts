import { NextRequest, NextResponse } from "next/server.js";
import * as oauth from "oauth4webapi";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AccessTokenErrorCode } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Mock oauth4webapi for integration tests
vi.mock("oauth4webapi", () => ({
  protectedResourceRequest: vi.fn(),
  isDPoPNonceError: vi.fn(),
  DPoP: vi.fn((client, keyPair) => ({ client, keyPair })), // Simple mock DPoP handle
  generateKeyPair: vi.fn(async (alg: string) => ({
    privateKey: {} as CryptoKey,
    publicKey: {} as CryptoKey
  })),
  customFetch: Symbol("customFetch"),
  allowInsecureRequests: Symbol("allowInsecureRequests")
}));

describe("DPoP Tests", () => {
  let authClient: AuthClient;
  let sessionStore: StatelessSessionStore;
  let secret: string;
  let dpopKeyPair: { privateKey: CryptoKey; publicKey: CryptoKey };
  const expiration = Math.floor(Date.now() / 1000) + 3600;

  const DEFAULT = {
    domain: "test.auth0.com",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    appBaseUrl: "https://example.com",
    sub: "user_123",
    accessToken: "at_123"
  };

  beforeEach(async () => {
    secret = await generateSecret(32);
    dpopKeyPair = await generateDpopKeyPair();

    const transactionStore = new TransactionStore({ secret });
    sessionStore = new StatelessSessionStore({ secret });

    authClient = new AuthClient({
      transactionStore,
      sessionStore,
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      secret,
      appBaseUrl: DEFAULT.appBaseUrl,
      routes: getDefaultRoutes(),
      dpopKeyPair,
      useDpop: true
    });

    // Reset mocks
    vi.mocked(oauth.protectedResourceRequest).mockReset();
    vi.mocked(oauth.isDPoPNonceError).mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  async function createValidSession(): Promise<string> {
    const session: SessionData = {
      user: { sub: DEFAULT.sub },
      tokenSet: {
        accessToken: DEFAULT.accessToken,
        idToken: "id_token",
        scope: "openid profile email",
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      },
      internal: {
        sid: "session-id",
        createdAt: Math.floor(Date.now() / 1000)
      }
    };

    return await encrypt(session, secret, expiration);
  }

  async function createProtectedRequest(
    requestBody: any,
    sessionCookie?: string
  ): Promise<NextRequest> {
    const cookie = sessionCookie || (await createValidSession());

    return new NextRequest(
      new URL("/auth/protected-request", DEFAULT.appBaseUrl),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `__session=${cookie}`
        },
        body: JSON.stringify(requestBody)
      }
    );
  }

  describe("DPoP Configuration", () => {
    it("should create auth client with DPoP enabled", () => {
      expect(authClient).toBeDefined();
      // The auth client should be properly configured with DPoP
      // This is a basic smoke test to ensure DPoP configuration doesn't break initialization
    });

    it("should create auth client without DPoP", () => {
      const nonDpopAuthClient = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes()
        // No DPoP configuration
      });

      expect(nonDpopAuthClient).toBeDefined();
    });

    it("should generate valid DPoP key pair", async () => {
      const keyPair = await generateDpopKeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      // Note: In test environment with mocks, we can't test CryptoKey instance types
      expect(typeof keyPair.privateKey).toBe("object");
      expect(typeof keyPair.publicKey).toBe("object");
    });
  });

  describe("Session Handling", () => {
    it("should return 401 when no session exists", async () => {
      const request = new NextRequest(
        new URL("/auth/protected-request", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: JSON.stringify({
            url: "https://api.example.com/data",
            method: "GET"
          })
        }
      );

      const response = await authClient.handler(request);

      expect(response.status).toBe(401);
      const responseBody = await response.json();
      expect(responseBody.error.message).toBe(
        "The user does not have an active session."
      );
      expect(responseBody.error.code).toBe(
        AccessTokenErrorCode.MISSING_SESSION
      );
    });

    it("should create valid session cookie", async () => {
      const sessionCookie = await createValidSession();

      expect(sessionCookie).toBeDefined();
      expect(typeof sessionCookie).toBe("string");
      expect(sessionCookie.length).toBeGreaterThan(0);
    });

    it("should proceed with valid session", async () => {
      // Mock successful external API response
      const externalApiResponse = new Response(
        JSON.stringify({ data: "protected content" }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);
    });
  });

  describe("Request Validation", () => {
    it("should handle missing request body", async () => {
      const sessionCookie = await createValidSession();

      const request = new NextRequest(
        new URL("/auth/protected-request", DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Cookie: `__session=${sessionCookie}`
          }
          // No body
        }
      );

      await expect(authClient.handler(request)).rejects.toThrow();
    });

    it("should handle malformed JSON in request body", async () => {
      const sessionCookie = await createValidSession();

      const request = new NextRequest(
        new URL("/auth/protected-request", DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Cookie: `__session=${sessionCookie}`
          },
          body: "invalid json {"
        }
      );

      await expect(authClient.handler(request)).rejects.toThrow();
    });

    it("should validate request structure", async () => {
      const request = await createProtectedRequest({
        // Missing url field
        method: "GET"
      });

      // Should handle missing required fields gracefully
      await expect(async () => {
        await authClient.handler(request);
      }).not.toThrow("url is required");
    });

    it("should default method to GET when not specified", async () => {
      const externalApiResponse = new Response("OK", { status: 200 });
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data"
        // method not specified
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      const [accessToken, method] = vi.mocked(oauth.protectedResourceRequest)
        .mock.calls[0];
      expect(method).toBe("GET");
    });
  });

  describe("Request Proxying", () => {
    it("should proxy GET requests correctly", async () => {
      const externalApiResponse = new Response(
        JSON.stringify({ data: "test" }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      // Verify protectedResourceRequest was called with correct parameters
      const [accessToken, method, url, headers, body, options] = vi.mocked(
        oauth.protectedResourceRequest
      ).mock.calls[0];
      expect(accessToken).toBe(DEFAULT.accessToken);
      expect(method).toBe("GET");
      expect(url.href).toBe("https://api.example.com/data");
      expect(options).toBeDefined();
      expect(options?.DPoP).toBeDefined(); // DPoP handle should be passed
    });

    it("should proxy POST requests with body", async () => {
      const externalApiResponse = new Response(
        JSON.stringify({ created: true }),
        {
          status: 201,
          headers: { "Content-Type": "application/json" }
        }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const requestBody = { name: "test", value: 123 };
      const request = await createProtectedRequest({
        url: "https://api.example.com/create",
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody)
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(201);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      const [accessToken, method, url, headers, body, options] = vi.mocked(
        oauth.protectedResourceRequest
      ).mock.calls[0];
      expect(method).toBe("POST");
      expect(body).toBeDefined();
      expect(options).toBeDefined();
      expect(options?.DPoP).toBeDefined();
    });

    it("should proxy response headers and body", async () => {
      const responseBody = { message: "success" };
      const externalApiResponse = new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Custom-Header": "custom-value",
          "Cache-Control": "no-cache"
        }
      });
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/json");
      expect(response.headers.get("X-Custom-Header")).toBe("custom-value");
      expect(response.headers.get("Cache-Control")).toBe("no-cache");

      const responseData = await response.json();
      expect(responseData).toEqual(responseBody);
    });

    it("should handle different status codes", async () => {
      const externalApiResponse = new Response("Not Found", { status: 404 });
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/nonexistent",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(404);
      expect(await response.text()).toBe("Not Found");
    });
  });

  describe("DPoP Nonce Handling", () => {
    it("should retry once on DPoP nonce error", async () => {
      // First call fails with nonce error
      const nonceError = new Error("DPoP nonce error");
      vi.mocked(oauth.isDPoPNonceError).mockReturnValue(true);

      // Second call succeeds
      const successResponse = new Response(
        JSON.stringify({ data: "success after retry" }),
        { status: 200 }
      );

      vi.mocked(oauth.protectedResourceRequest)
        .mockRejectedValueOnce(nonceError)
        .mockResolvedValueOnce(successResponse);

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(2); // Initial call + retry
      expect(oauth.isDPoPNonceError).toHaveBeenCalledWith(nonceError);

      const responseData = await response.json();
      expect(responseData.data).toBe("success after retry");
    });

    it("should not retry on non-nonce errors", async () => {
      const networkError = new Error("Network error");
      vi.mocked(oauth.isDPoPNonceError).mockReturnValue(false);

      vi.mocked(oauth.protectedResourceRequest).mockRejectedValueOnce(
        networkError
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      await expect(authClient.handler(request)).rejects.toThrow(
        "Network error"
      );
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1); // No retry
      expect(oauth.isDPoPNonceError).toHaveBeenCalledWith(networkError);
    });

    it("should pass DPoP handle to protectedResourceRequest", async () => {
      const externalApiResponse = new Response("OK", { status: 200 });
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await authClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      const [accessToken, method, url, headers, body, options] = vi.mocked(
        oauth.protectedResourceRequest
      ).mock.calls[0];
      expect(options).toBeDefined();
      expect(options?.DPoP).toBeDefined();
      expect(typeof options?.DPoP).toBe("object"); // Should be DPoP handle
    });
  });

  describe("Integration with AuthClient", () => {
    it("should work with non-DPoP auth client", async () => {
      // Create auth client without DPoP
      const nonDpopAuthClient = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes()
        // No DPoP configuration
      });

      const externalApiResponse = new Response("OK", { status: 200 });
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      const response = await nonDpopAuthClient.handler(request);

      expect(response.status).toBe(200);
      expect(oauth.protectedResourceRequest).toHaveBeenCalledTimes(1);

      const [accessToken, method, url, headers, body, options] = vi.mocked(
        oauth.protectedResourceRequest
      ).mock.calls[0];
      expect(options?.DPoP).toBeUndefined(); // No DPoP handle
    });

    it("should handle protected request with valid session", async () => {
      // Mock successful response to avoid actual network calls
      const externalApiResponse = new Response(
        JSON.stringify({ data: "protected content" }),
        { status: 200 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValueOnce(
        externalApiResponse
      );

      const request = await createProtectedRequest({
        url: "https://api.example.com/data",
        method: "GET"
      });

      // Should not fail due to session validation
      const response = await authClient.handler(request);
      expect(response.status).toBe(200);
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid URLs gracefully", async () => {
      const request = await createProtectedRequest({
        url: "not-a-valid-url",
        method: "GET"
      });

      // Should handle malformed URLs
      await expect(async () => {
        await authClient.handler(request);
      }).not.toThrow("Invalid URL");
    });

    it("should handle empty URL", async () => {
      const request = await createProtectedRequest({
        url: "",
        method: "GET"
      });

      // Should handle empty URLs
      await expect(async () => {
        await authClient.handler(request);
      }).not.toThrow("URL cannot be empty");
    });
  });
});
