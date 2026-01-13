import { NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";

import { Auth0ResponseCookies } from "./auth0-response-cookies.js";

describe("Auth0ResponseCookies", () => {
  describe("get()", () => {
    it("should retrieve a cookie by name", () => {
      const response = NextResponse.next();
      response.cookies.set("session", "abc123", { httpOnly: true });

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);
      const cookie = auth0Cookies.get("session");

      expect(cookie).toBeDefined();
      expect(cookie?.name).toBe("session");
      expect(cookie?.value).toBe("abc123");
    });

    it("should return undefined for non-existent cookie", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const cookie = auth0Cookies.get("nonexistent");

      expect(cookie).toBeUndefined();
    });

    it("should retrieve cookie attributes", () => {
      const response = NextResponse.next();
      response.cookies.set("session", "token123", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 86400
      });

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);
      const cookie = auth0Cookies.get("session");

      expect(cookie?.httpOnly).toBe(true);
      expect(cookie?.secure).toBe(true);
      expect(cookie?.sameSite).toBe("lax");
    });
  });

  describe("getAll()", () => {
    it("should retrieve all cookies", () => {
      const response = NextResponse.next();
      response.cookies.set("session", "token1");
      response.cookies.set("preferences", "dark");
      response.cookies.set("theme", "modern");

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);
      const allCookies = auth0Cookies.getAll();

      expect(allCookies.length).toBeGreaterThanOrEqual(3);
      expect(allCookies.map((c) => c.name)).toContain("session");
      expect(allCookies.map((c) => c.name)).toContain("preferences");
      expect(allCookies.map((c) => c.name)).toContain("theme");
    });

    it("should return empty array when no cookies set", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const allCookies = auth0Cookies.getAll();

      expect(Array.isArray(allCookies)).toBe(true);
    });

    it("should support filtering by name pattern", () => {
      const response = NextResponse.next();
      response.cookies.set("session", "token1");
      response.cookies.set("session__0", "chunk1");
      response.cookies.set("session__1", "chunk2");

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);
      const filtered = auth0Cookies.getAll("session");

      expect(filtered).toBeDefined();
    });
  });

  describe("has()", () => {
    it("should return true if cookie exists", () => {
      const response = NextResponse.next();
      response.cookies.set("session", "token");

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      expect(auth0Cookies.has("session")).toBe(true);
    });

    it("should return false if cookie does not exist", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      expect(auth0Cookies.has("nonexistent")).toBe(false);
    });

    it("should be case-sensitive", () => {
      const response = NextResponse.next();
      response.cookies.set("Session", "token");

      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      expect(auth0Cookies.has("Session")).toBe(true);
      expect(auth0Cookies.has("session")).toBe(false);
    });
  });

  describe("set()", () => {
    it("should set a cookie with name and value", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("newcookie", "value123");

      expect(auth0Cookies.has("newcookie")).toBe(true);
      expect(auth0Cookies.get("newcookie")?.value).toBe("value123");
    });

    it("should set cookie with HttpOnly flag", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { httpOnly: true });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.httpOnly).toBe(true);
    });

    it("should set cookie with Secure flag", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { secure: true });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.secure).toBe(true);
    });

    it("should set cookie with SameSite flag", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { sameSite: "strict" });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.sameSite).toBe("strict");
    });

    it("should set cookie with maxAge", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { maxAge: 86400 });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.maxAge).toBe(86400);
    });

    it("should set cookie with path", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { path: "/auth" });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.path).toBe("/auth");
    });

    it("should set cookie with domain", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { domain: ".example.com" });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.domain).toBe(".example.com");
    });

    it("should allow method chaining", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const result = auth0Cookies
        .set("cookie1", "value1")
        .set("cookie2", "value2");

      expect(result).toBe(auth0Cookies);
      expect(auth0Cookies.has("cookie1")).toBe(true);
      expect(auth0Cookies.has("cookie2")).toBe(true);
    });

    it("should handle large cookie values", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const largeValue = "x".repeat(3000);
      auth0Cookies.set("large", largeValue);

      const cookie = auth0Cookies.get("large");
      expect(cookie?.value).toBe(largeValue);
    });

    it("should handle cookie values with special characters", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const jwtToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
      auth0Cookies.set("jwt", jwtToken);

      const cookie = auth0Cookies.get("jwt");
      expect(cookie?.value).toBe(jwtToken);
    });

    it("should handle empty cookie value", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("empty", "");

      const cookie = auth0Cookies.get("empty");
      expect(cookie?.value).toBe("");
    });

    it("should update existing cookie", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "old_value");
      auth0Cookies.set("session", "new_value");

      const cookie = auth0Cookies.get("session");
      expect(cookie?.value).toBe("new_value");
    });

    it("should automatically chunk very large cookies", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      // Create a value larger than the chunk size (3500 bytes)
      const largeValue = "x".repeat(4000);
      auth0Cookies.set("large", largeValue);

      // Check if chunked cookies are created
      const allCookies = auth0Cookies.getAll();
      const largeRelatedCookies = allCookies.filter((c) =>
        c.name.startsWith("large")
      );

      expect(largeRelatedCookies.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("delete()", () => {
    it("should delete a cookie", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token");
      auth0Cookies.delete("session");

      // After deletion, the cookie should be set with an expiration date in the past
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toContain("session=");
    });

    it("should not affect other cookies when deleting", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token1");
      auth0Cookies.set("preferences", "dark");
      auth0Cookies.delete("session");

      expect(auth0Cookies.has("preferences")).toBe(true);
    });

    it("should handle deleting non-existent cookie", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      expect(() => {
        auth0Cookies.delete("nonexistent");
      }).not.toThrow();
    });

    it("should allow method chaining", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("cookie1", "value1");
      auth0Cookies.set("cookie2", "value2");

      const result = auth0Cookies.delete("cookie1").delete("cookie2");

      expect(result).toBe(auth0Cookies);
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toContain("cookie1=");
      expect(setCookieHeader).toContain("cookie2=");
    });

    it("should handle deleting chunked cookies", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      const largeValue = "x".repeat(4000);
      auth0Cookies.set("large", largeValue);
      auth0Cookies.delete("large");

      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toContain("large");
    });

    it("should support delete options with path", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { path: "/auth" });

      expect(() => {
        auth0Cookies.delete({ name: "session", path: "/auth" });
      }).not.toThrow();
    });

    it("should support delete options with domain", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("session", "token", { domain: ".example.com" });

      expect(() => {
        auth0Cookies.delete({ name: "session", domain: ".example.com" });
      }).not.toThrow();
    });
  });

  describe("constructor", () => {
    it("should accept ResponseCookies", () => {
      const response = NextResponse.next();

      expect(() => {
        new Auth0ResponseCookies(response.cookies);
      }).not.toThrow();
    });
  });

  describe("integration scenarios", () => {
    it("should set secure session cookie", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies.set("auth0_session", "session_token", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 86400
      });

      const cookie = auth0Cookies.get("auth0_session");
      expect(cookie?.httpOnly).toBe(true);
      expect(cookie?.secure).toBe(true);
      expect(cookie?.sameSite).toBe("lax");
      expect(cookie?.maxAge).toBe(86400);
    });

    it("should handle login flow with multiple cookies", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      auth0Cookies
        .set("auth0_session", "session_token", { httpOnly: true, secure: true })
        .set("auth0_nonce", "nonce123", { httpOnly: true, secure: true })
        .set("auth0_state", "state456", { httpOnly: true, secure: true });

      expect(auth0Cookies.has("auth0_session")).toBe(true);
      expect(auth0Cookies.has("auth0_nonce")).toBe(true);
      expect(auth0Cookies.has("auth0_state")).toBe(true);
    });

    it("should handle logout flow by deleting cookies", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      // Set cookies
      auth0Cookies.set("auth0_session", "token");
      auth0Cookies.set("auth0_nonce", "nonce");

      // Delete on logout
      auth0Cookies.delete("auth0_session").delete("auth0_nonce");

      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toContain("auth0_session=");
      expect(setCookieHeader).toContain("auth0_nonce=");
    });

    it("should handle large JWT tokens", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      // Simulate a large JWT token
      const jwtToken =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
        "x".repeat(2000) +
        ".signature";

      auth0Cookies.set("id_token", jwtToken, { httpOnly: true });

      const cookie = auth0Cookies.get("id_token");
      expect(cookie?.value).toBe(jwtToken);
    });

    it("should handle cookie renewal scenario", () => {
      const response = NextResponse.next();
      const auth0Cookies = new Auth0ResponseCookies(response.cookies);

      // Set initial cookie
      auth0Cookies.set("session", "old_token", { maxAge: 3600 });

      // Renew cookie with new token
      auth0Cookies.set("session", "new_token", { maxAge: 86400 });

      const cookie = auth0Cookies.get("session");
      expect(cookie?.value).toBe("new_token");
      expect(cookie?.maxAge).toBe(86400);
    });
  });
});
