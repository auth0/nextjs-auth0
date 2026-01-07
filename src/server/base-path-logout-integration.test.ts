import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Auth0Client } from "./client.js";
import { deleteChunkedCookie } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";
import { Auth0RequestCookies, Auth0ResponseCookies } from "./http/index.js";

describe("Base path and cookie configuration tests", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    vi.clearAllMocks();
    vi.resetModules();
    // Clear any existing environment variables
    delete process.env.NEXT_PUBLIC_BASE_PATH;
    delete process.env.AUTH0_COOKIE_PATH;
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
    delete process.env.NEXT_PUBLIC_BASE_PATH;
    delete process.env.AUTH0_COOKIE_PATH;
  });

  describe("Logout integration with base paths", () => {
    it("should reproduce the bug scenario: cookies set with base path should be deleted with same path", async () => {
      // Set up environment with base path
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

      // Create Auth0Client which should auto-detect the base path
      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com/dashboard",
        secret: "test-secret-that-is-long-enough-for-jwt"
      });

      // Get the session store
      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;

      // Verify that the session store has the correct path configuration
      expect((sessionStore as any).cookieConfig.path).toBe("/dashboard");

      // Simulate cookie deletion during logout
      const mockResCookies = new ResponseCookies(new Headers());
      const mockReqCookies = new RequestCookies(new Headers()) as any;

      // Mock the get method to simulate an existing session cookie
      mockReqCookies.get = () => ({ value: "mock-session-value" });
      mockReqCookies.getAll = () => [];

      // Call delete method (this would be called during logout)
      await sessionStore.delete(new Auth0RequestCookies(mockReqCookies), new Auth0ResponseCookies(mockResCookies));

      // Verify that the cookie deletion header includes the correct path
      const cookieHeader = mockResCookies.toString();

      // The cookie should be deleted with the same path it was set with
      expect(cookieHeader).toContain("Path=/dashboard");
      expect(cookieHeader).toContain("Max-Age=0");
    });

    it("should work correctly without base path (backward compatibility)", async () => {
      // No base path set
      delete process.env.NEXT_PUBLIC_BASE_PATH;

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com",
        secret: "test-secret-that-is-long-enough-for-jwt"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;

      // Should default to root path
      expect((sessionStore as any).cookieConfig.path).toBe("/");

      // Test deletion
      const mockResCookies = new ResponseCookies(new Headers());
      const mockReqCookies = new RequestCookies(new Headers()) as any;

      mockReqCookies.get = () => ({ value: "mock-session-value" });
      mockReqCookies.getAll = () => [];

      await sessionStore.delete(new Auth0RequestCookies(mockReqCookies), new Auth0ResponseCookies(mockResCookies));

      const cookieHeader = mockResCookies.toString();

      // Should use root path or no path specified
      expect(cookieHeader).toContain("Max-Age=0");
    });

    it("should prioritize explicit cookie path over base path", async () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com",
        secret: "test-secret-that-is-long-enough-for-jwt",
        session: {
          cookie: {
            path: "/custom-path"
          }
        }
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;

      // Should use the explicit path, not the base path
      expect((sessionStore as any).cookieConfig.path).toBe("/custom-path");
    });
  });

  describe("Cookie deletion functions", () => {
    let mockResCookies: ResponseCookies;

    beforeEach(() => {
      // Create a mock ResponseCookies object
      const mockHeaders = new Headers();
      mockResCookies = new ResponseCookies(mockHeaders);
    });

    it("should delete cookie with default path when no path is specified", () => {
      const auth0ResCookies = new Auth0ResponseCookies(mockResCookies);
      auth0ResCookies.delete("test-cookie");

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("test-cookie=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/");
    });

    it("should delete cookie with specified path", () => {
      const auth0ResCookies = new Auth0ResponseCookies(mockResCookies);
      auth0ResCookies.delete({
        name: "test-cookie",
        path: "/dashboard"
      });

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("test-cookie=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/dashboard");
    });

    it("should delete cookie with root path explicitly", () => {
      const auth0ResCookies = new Auth0ResponseCookies(mockResCookies);
      auth0ResCookies.delete({
        name: "test-cookie",
        path: "/"
      });

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("test-cookie=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/");
    });

    it("should handle chunked cookie deletion with path", () => {
      const mockReqCookies = {
        getAll: () => [
          { name: "test-cookie__0", value: "chunk1" },
          { name: "test-cookie__1", value: "chunk2" }
        ]
      } as any;

      deleteChunkedCookie(
        "test-cookie",
        new Auth0RequestCookies(mockReqCookies),
        new Auth0ResponseCookies(mockResCookies),
        false,
        { path: "/dashboard" }
      );

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("test-cookie=");
      expect(cookieHeader).toContain("Path=/dashboard");
      expect(cookieHeader).toContain("test-cookie__0=");
      expect(cookieHeader).toContain("test-cookie__1=");
    });
  });

  describe("Auth0Client constructor base path auto-detection", () => {
    it("should use NEXT_PUBLIC_BASE_PATH for cookie paths when configured", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      // Access private properties through any casting for testing
      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      const transactionStore = (client as any)
        .transactionStore as TransactionStore;

      expect((sessionStore as any).cookieConfig.path).toBe("/dashboard");
      expect((transactionStore as any).cookieOptions.path).toBe("/dashboard");
    });

    it("should use explicit AUTH0_COOKIE_PATH over base path", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      process.env.AUTH0_COOKIE_PATH = "/custom";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      expect((sessionStore as any).cookieConfig.path).toBe("/custom");
    });

    it("should use client options over environment variables", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";
      process.env.AUTH0_COOKIE_PATH = "/custom";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com",
        session: {
          cookie: {
            path: "/explicit"
          }
        },
        transactionCookie: {
          path: "/txn-explicit"
        }
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      const transactionStore = (client as any)
        .transactionStore as TransactionStore;

      expect((sessionStore as any).cookieConfig.path).toBe("/explicit");
      expect((transactionStore as any).cookieOptions.path).toBe(
        "/txn-explicit"
      );
    });

    it("should default to root path when no base path is configured", () => {
      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      const transactionStore = (client as any)
        .transactionStore as TransactionStore;

      expect((sessionStore as any).cookieConfig.path).toBe("/");
      expect((transactionStore as any).cookieOptions.path).toBe("/");
    });
  });

  describe("Session store cookie deletion with paths", () => {
    it("should delete session cookies with configured path during logout", async () => {
      const mockReqCookies = {
        get: vi.fn().mockReturnValue({ value: "encrypted-session" }),
        getAll: vi.fn().mockReturnValue([])
      } as any;

      const mockResCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatelessSessionStore({
        secret: "test-secret",
        cookieOptions: {
          name: "__session",
          path: "/dashboard"
        }
      });

      await sessionStore.delete(new Auth0RequestCookies(mockReqCookies), new Auth0ResponseCookies(mockResCookies));

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("__session=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/dashboard");
    });
  });

  describe("Transaction store cookie deletion with paths", () => {
    it("should delete transaction cookies with configured path", async () => {
      const mockResCookies = new ResponseCookies(new Headers());

      const transactionStore = new TransactionStore({
        secret: "test-secret",
        cookieOptions: {
          path: "/dashboard"
        }
      });

      await transactionStore.delete(new Auth0ResponseCookies(mockResCookies), "test-state");

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("__txn_test-state=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/dashboard");
    });

    it("should delete all transaction cookies with configured path", async () => {
      const mockReqCookies = {
        getAll: () => [
          { name: "__txn_state1", value: "value1" },
          { name: "__txn_state2", value: "value2" },
          { name: "other-cookie", value: "other" }
        ]
      } as any;

      const mockResCookies = new ResponseCookies(new Headers());

      const transactionStore = new TransactionStore({
        secret: "test-secret",
        cookieOptions: {
          path: "/dashboard"
        }
      });

      await transactionStore.deleteAll(new Auth0RequestCookies(mockReqCookies), new Auth0ResponseCookies(mockResCookies));

      const cookieHeader = mockResCookies.toString();
      expect(cookieHeader).toContain("__txn_state1=");
      expect(cookieHeader).toContain("__txn_state2=");
      expect(cookieHeader).toContain("Max-Age=0");
      expect(cookieHeader).toContain("Path=/dashboard");
      expect(cookieHeader).not.toContain("other-cookie=; Max-Age=0");
    });
  });

  describe("Edge Cases", () => {
    it("should handle nested base paths correctly", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/app/dashboard";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      expect((sessionStore as any).cookieConfig.path).toBe("/app/dashboard");
    });

    it("should handle base path with trailing slash", () => {
      process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard/";

      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      expect((sessionStore as any).cookieConfig.path).toBe("/dashboard/");
    });

    it("should handle empty path correctly", () => {
      const auth0ResponseCookies = new Auth0ResponseCookies(new ResponseCookies(new Headers()));
      auth0ResponseCookies.delete({
        name: "test-cookie",
        path: ""
      });

      // Should not throw and should create valid cookie deletion
      expect(true).toBe(true);
    });
  });

  describe("Backward Compatibility", () => {
    it("should maintain existing behavior when no base path is configured", () => {
      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com"
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      const transactionStore = (client as any)
        .transactionStore as TransactionStore;

      // Should default to root path as before
      expect((sessionStore as any).cookieConfig.path).toBe("/");
      expect((transactionStore as any).cookieOptions.path).toBe("/");
    });

    it("should not break existing explicit cookie configurations", () => {
      const client = new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        appBaseUrl: "https://app.example.com",
        session: {
          cookie: {
            path: "/legacy-path",
            name: "legacy-session"
          }
        }
      });

      const sessionStore = (client as any)
        .sessionStore as StatelessSessionStore;
      expect((sessionStore as any).cookieConfig.path).toBe("/legacy-path");
      expect((sessionStore as any).sessionCookieName).toBe("legacy-session");
    });
  });
});
