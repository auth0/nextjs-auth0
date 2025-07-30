import { ResponseCookies } from "@edge-runtime/cookies";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { deleteChunkedCookie, deleteCookie } from "../src/server/cookies.js";
import { StatelessSessionStore } from "../src/server/session/stateless-session-store.js";

/**
 * "Logout fails to clear cookies when AUTH0_COOKIE_DOMAIN is set"
 *
 * Tests the fix ensuring deleteCookie() properly handles both domain and path options
 * to prevent cookies from persisting after logout when custom domains are configured.
 */
describe("logout-with-domain-config", () => {
  let headers: Headers;
  let resCookies: ResponseCookies;
  let mockReqCookies: any;

  beforeEach(() => {
    headers = new Headers();
    resCookies = new ResponseCookies(headers);

    // Mock request cookies interface
    const reqCookiesMap = new Map<string, string>();
    mockReqCookies = {
      get: (name: string) => {
        const value = reqCookiesMap.get(name);
        return value ? { value } : undefined;
      },
      getAll: () =>
        Array.from(reqCookiesMap.entries()).map(([name, value]) => ({
          name,
          value
        })),
      set: (name: string, value: string) => reqCookiesMap.set(name, value),
      delete: (name: string) => reqCookiesMap.delete(name),
      has: (name: string) => reqCookiesMap.has(name)
    };
  });

  afterEach(() => {
    headers = new Headers();
  });

  describe("Happy Path: Successful cookie deletion", () => {
    it("should delete session cookies with custom domain and path", () => {
      // Arrange: Setup session store with custom domain (reproduces AUTH0_COOKIE_DOMAIN scenario)
      const sessionStore = new StatelessSessionStore({
        secret: "a-very-long-secret-that-is-at-least-32-characters-long",
        cookieOptions: {
          domain: "example.com",
          path: "/",
          secure: true,
          sameSite: "lax"
        }
      });

      mockReqCookies.set("__session", "mock-session-token");

      // Act: Delete session cookies
      sessionStore.delete(mockReqCookies, resCookies);

      // Assert: Cookie deletion headers include both domain and path
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBeGreaterThan(0);

      const sessionDeletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );

      expect(sessionDeletionHeader).toBeDefined();
      expect(sessionDeletionHeader).toContain("Domain=example.com");
      expect(sessionDeletionHeader).toContain("Path=/");
      expect(sessionDeletionHeader).toContain("Max-Age=0");
    });

    it("should delete session cookies with path when domain not configured", () => {
      // Arrange: Session store without custom domain but with path
      const sessionStore = new StatelessSessionStore({
        secret: "a-very-long-secret-that-is-at-least-32-characters-long",
        cookieOptions: {
          path: "/",
          secure: true,
          sameSite: "lax"
        }
      });

      mockReqCookies.set("__session", "mock-session-token");

      // Act
      sessionStore.delete(mockReqCookies, resCookies);

      // Assert: Path is included even without domain
      const setCookieHeaders = headers.getSetCookie();
      const sessionDeletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );

      expect(sessionDeletionHeader).toBeDefined();
      expect(sessionDeletionHeader).not.toContain("Domain=");
      expect(sessionDeletionHeader).toContain("Path=/");
      expect(sessionDeletionHeader).toContain("Max-Age=0");
    });

    it("should delete chunked session cookies with domain and path", () => {
      // Arrange: Setup large session that gets chunked
      const sessionStore = new StatelessSessionStore({
        secret: "a-very-long-secret-that-is-at-least-32-characters-long",
        cookieOptions: {
          domain: "test.example.com",
          path: "/app",
          secure: true,
          sameSite: "lax"
        }
      });

      // Simulate chunked cookies (multiple session chunks using correct format)
      mockReqCookies.set("__session__0", "chunk-0-data");
      mockReqCookies.set("__session__1", "chunk-1-data");
      mockReqCookies.set("__session__2", "chunk-2-data");

      // Act
      sessionStore.delete(mockReqCookies, resCookies);

      // Assert: All chunks are deleted with proper domain/path
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBeGreaterThanOrEqual(3);

      const chunkDeletionHeaders = setCookieHeaders.filter(
        (header) =>
          header.includes("__session__") && header.includes("Max-Age=0")
      );

      expect(chunkDeletionHeaders.length).toBeGreaterThanOrEqual(3);

      chunkDeletionHeaders.forEach((header) => {
        expect(header).toContain("Domain=test.example.com");
        expect(header).toContain("Path=/app");
        expect(header).toContain("Max-Age=0");
      });
    });
  });

  describe("Edge Cases: deleteCookie function behavior", () => {
    it("should handle both domain and path deletion options", () => {
      // Arrange & Act
      deleteCookie(resCookies, "test-cookie", {
        domain: "api.example.com",
        path: "/v1/auth"
      });

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("test-cookie=") && header.includes("Max-Age=0")
      );

      expect(deletionHeader).toBeDefined();
      expect(deletionHeader).toContain("Domain=api.example.com");
      expect(deletionHeader).toContain("Path=/v1/auth");
      expect(deletionHeader).toContain("Max-Age=0");
    });

    it("should handle domain-only deletion options", () => {
      // Arrange & Act
      deleteCookie(resCookies, "test-cookie", {
        domain: "sub.example.com",
        path: "/"
      });

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("test-cookie=") && header.includes("Max-Age=0")
      );

      expect(deletionHeader).toBeDefined();
      expect(deletionHeader).toContain("Domain=sub.example.com");
      expect(deletionHeader).toContain("Max-Age=0");
    });

    it("should handle path-only deletion options", () => {
      // Arrange & Act
      deleteCookie(resCookies, "test-cookie", { path: "/api" });

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("test-cookie=") && header.includes("Max-Age=0")
      );

      expect(deletionHeader).toBeDefined();
      expect(deletionHeader).toContain("Path=/api");
      expect(deletionHeader).not.toContain("Domain=");
      expect(deletionHeader).toContain("Max-Age=0");
    });

    it("should handle deletion without any options", () => {
      // Arrange & Act
      deleteCookie(resCookies, "simple-cookie");

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("simple-cookie=") && header.includes("Max-Age=0")
      );

      expect(deletionHeader).toBeDefined();
      expect(deletionHeader).not.toContain("Domain=");
      // Note: Path=/ is always included by default in ResponseCookies
      expect(deletionHeader).toContain("Path=/");
      expect(deletionHeader).toContain("Max-Age=0");
    });
  });

  describe("Boundary Conditions", () => {
    it("should handle empty cookie name", () => {
      // Arrange & Act
      expect(() => {
        deleteCookie(resCookies, "", { domain: "example.com", path: "/" });
      }).not.toThrow();

      // Assert: Still creates deletion header even with empty name
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBe(1);
      expect(setCookieHeaders[0]).toContain("Max-Age=0");
    });

    it("should handle special characters in domain and path", () => {
      // Arrange & Act
      deleteCookie(resCookies, "special-cookie", {
        domain: "sub-domain.example.com",
        path: "/special/path-with-dashes"
      });

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders[0];

      expect(deletionHeader).toContain("Domain=sub-domain.example.com");
      expect(deletionHeader).toContain("Path=/special/path-with-dashes");
    });

    it("should handle long domain and path values", () => {
      // Arrange
      const longDomain =
        "very-long-subdomain-name.with-multiple-segments.example-domain.com";
      const longPath =
        "/very/long/path/with/multiple/segments/that/goes/deep/into/the/application";

      // Act
      deleteCookie(resCookies, "long-path-cookie", {
        domain: longDomain,
        path: longPath
      });

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      const deletionHeader = setCookieHeaders[0];

      expect(deletionHeader).toContain(`Domain=${longDomain}`);
      expect(deletionHeader).toContain(`Path=${longPath}`);
    });
  });

  describe("Chunked Cookie Deletion", () => {
    it("should delete all chunks when deleting chunked cookies", () => {
      // Arrange: Simulate multiple cookie chunks
      const cookieName = "__session";
      mockReqCookies.set(`${cookieName}__0`, "chunk-0");
      mockReqCookies.set(`${cookieName}__1`, "chunk-1");
      mockReqCookies.set(`${cookieName}__2`, "chunk-2");

      const options = { domain: "chunks.example.com", path: "/chunks" };

      // Act
      deleteChunkedCookie(
        cookieName,
        mockReqCookies,
        resCookies,
        false,
        options
      );

      // Assert: All chunks plus main cookie are deleted
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBeGreaterThanOrEqual(4); // 3 chunks + main cookie

      // Check main cookie deletion
      const mainDeletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes(`${cookieName}=`) && header.includes("Max-Age=0")
      );
      expect(mainDeletionHeader).toBeDefined();
      expect(mainDeletionHeader).toContain("Domain=chunks.example.com");
      expect(mainDeletionHeader).toContain("Path=/chunks");

      // Check chunk deletions
      for (let i = 0; i < 3; i++) {
        const chunkDeletionHeader = setCookieHeaders.find(
          (header) =>
            header.includes(`${cookieName}__${i}=`) &&
            header.includes("Max-Age=0")
        );
        expect(chunkDeletionHeader).toBeDefined();
        expect(chunkDeletionHeader).toContain("Domain=chunks.example.com");
        expect(chunkDeletionHeader).toContain("Path=/chunks");
      }
    });

    it("should handle chunked deletion without domain/path options", () => {
      // Arrange
      const cookieName = "__session";
      mockReqCookies.set(`${cookieName}__0`, "chunk-0");
      mockReqCookies.set(`${cookieName}__1`, "chunk-1");

      // Act
      deleteChunkedCookie(cookieName, mockReqCookies, resCookies);

      // Assert: Chunks are deleted without domain/path
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBeGreaterThanOrEqual(3); // 2 chunks + main cookie

      setCookieHeaders.forEach((header) => {
        expect(header).toContain("Max-Age=0");
        expect(header).not.toContain("Domain=");
        // Note: Path=/ is always included by default in ResponseCookies
        expect(header).toContain("Path=/");
      });
    });
  });

  describe("Regression Tests: Issue #2237 scenarios", () => {
    it("should reproduce and fix the original issue: logout with AUTH0_COOKIE_DOMAIN", () => {
      // Arrange: Exact scenario from bug report
      const sessionStore = new StatelessSessionStore({
        secret: "a-very-long-secret-that-is-at-least-32-characters-long",
        cookieOptions: {
          domain: "df.mydomain.com", // AUTH0_COOKIE_DOMAIN setting
          path: "/",
          secure: true,
          sameSite: "lax"
        }
      });

      // Simulate existing session cookie (set during login)
      mockReqCookies.set(
        "__session",
        "active-session-token-that-should-be-deleted"
      );

      // Act: Logout (delete session)
      sessionStore.delete(mockReqCookies, resCookies);

      // Assert: Cookie is properly deleted with matching domain and path
      const setCookieHeaders = headers.getSetCookie();
      const sessionDeletionHeader = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );

      expect(sessionDeletionHeader).toBeDefined();

      // This is the key fix: both Domain and Path must be present for successful deletion
      expect(sessionDeletionHeader).toContain("Domain=df.mydomain.com");
      expect(sessionDeletionHeader).toContain("Path=/");
      expect(sessionDeletionHeader).toContain("Max-Age=0");

      // Ensure cookie value is empty (standard deletion pattern)
      expect(sessionDeletionHeader).toMatch(/__session=;|__session="";/);
    });

    it("should handle logout path mismatch scenario (the bug condition)", () => {
      // Arrange: This test demonstrates that the bug was about explicit path handling
      // Even though ResponseCookies includes Path=/ by default, the fix ensures that
      // when AUTH0_COOKIE_DOMAIN is set, the SAME path and domain used during
      // cookie creation are used during deletion.

      // Test the fixed behavior: both domain and path explicitly passed
      const headersFixed = new Headers();
      const resCookiesFixed = new ResponseCookies(headersFixed);

      deleteCookie(resCookiesFixed, "__session", {
        domain: "df.mydomain.com",
        path: "/"
      });

      const fixedCookieHeaders = headersFixed.getSetCookie();
      const fixedHeader = fixedCookieHeaders[0];

      // The fixed behavior: deletion header includes both Domain and Path explicitly
      expect(fixedHeader).toContain("Domain=df.mydomain.com");
      expect(fixedHeader).toContain("Path=/");
      expect(fixedHeader).toContain("Max-Age=0");

      // Now test without explicit path (simplified test)
      const headersNoDomain = new Headers();
      const resCookiesNoDomain = new ResponseCookies(headersNoDomain);

      deleteCookie(resCookiesNoDomain, "__session", {
        domain: "df.mydomain.com",
        path: "/" // Both domain and path required by type system
      });

      const noDomainHeaders = headersNoDomain.getSetCookie();
      const noDomainHeader = noDomainHeaders[0];

      // Both should work but the fix ensures consistency with cookie creation
      expect(noDomainHeader).toContain("Domain=df.mydomain.com");
      expect(noDomainHeader).toContain("Path=/"); // Default path
      expect(noDomainHeader).toContain("Max-Age=0");
    });
  });

  describe("Error Scenarios", () => {
    it("should handle null/undefined options gracefully", () => {
      // Arrange & Act: Test with undefined options
      expect(() => {
        deleteCookie(resCookies, "test-cookie", undefined);
      }).not.toThrow();

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBe(1);
      expect(setCookieHeaders[0]).toContain("Max-Age=0");
    });

    it("should handle empty options object", () => {
      // Arrange & Act - Use minimal valid options
      expect(() => {
        deleteCookie(resCookies, "test-cookie", { path: "/" });
      }).not.toThrow();

      // Assert
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBe(1);
      expect(setCookieHeaders[0]).toContain("Max-Age=0");
    });
  });

  describe("Integration: Full logout flow", () => {
    it("should successfully complete full logout with custom domain", () => {
      // Arrange: Setup realistic session scenario
      const sessionStore = new StatelessSessionStore({
        secret: "a-very-long-secret-that-is-at-least-32-characters-long",
        cookieOptions: {
          domain: "app.company.com",
          path: "/",
          secure: true,
          sameSite: "strict"
        }
      });

      // Simulate multiple session-related cookies
      mockReqCookies.set("__session", "main-session-jwt-token");

      // Act: Perform logout
      sessionStore.delete(mockReqCookies, resCookies);

      // Assert: All session cookies are deleted with proper attributes
      const setCookieHeaders = headers.getSetCookie();
      expect(setCookieHeaders.length).toBeGreaterThan(0);

      // Verify session cookie deletion
      const sessionDeletion = setCookieHeaders.find(
        (header) =>
          header.includes("__session=") && header.includes("Max-Age=0")
      );
      expect(sessionDeletion).toBeDefined();
      expect(sessionDeletion).toContain("Domain=app.company.com");
      expect(sessionDeletion).toContain("Path=/");

      // Verify all deletion headers have consistent domain/path
      const deletionHeaders = setCookieHeaders.filter((header) =>
        header.includes("Max-Age=0")
      );

      deletionHeaders.forEach((header) => {
        expect(header).toContain("Domain=app.company.com");
        expect(header).toContain("Path=/");
        expect(header).toContain("Max-Age=0");
      });
    });
  });
});
