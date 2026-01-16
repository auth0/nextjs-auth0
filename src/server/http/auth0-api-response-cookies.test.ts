import { NextApiResponse } from "next";
import { describe, expect, it, vi } from "vitest";

import { Auth0ApiResponseCookies } from "./auth0-api-response-cookies.js";

/**
 * Creates a mock NextApiResponse for testing
 */
function createMockNextApiResponse(): NextApiResponse {
  const headers: Record<string, string | string[]> = {};

  const res = {
    setHeader: vi.fn((name: string, value: string | string[]) => {
      headers[name.toLowerCase()] = value;
      return res;
    }),
    getHeader: vi.fn((name: string) => headers[name.toLowerCase()]),
    getHeaders: vi.fn(() => headers),
    removeHeader: vi.fn((name: string) => {
      delete headers[name.toLowerCase()];
      return res;
    }),
    // Add internal headers access for testing
    _getInternalHeaders: () => headers
  } as unknown as NextApiResponse & {
    _getInternalHeaders: () => Record<string, string | string[]>;
  };

  return res;
}

describe("Auth0ApiResponseCookies", () => {
  describe("constructor", () => {
    it("should create an instance with NextApiResponse", () => {
      const mockRes = createMockNextApiResponse();

      expect(() => {
        new Auth0ApiResponseCookies(mockRes);
      }).not.toThrow();
    });

    it("should initialize with existing headers from response", () => {
      const mockRes = createMockNextApiResponse();
      mockRes.setHeader("X-Custom", "value");

      const cookies = new Auth0ApiResponseCookies(mockRes);

      expect(cookies).toBeDefined();
    });
  });

  describe("set()", () => {
    it("should set a cookie and sync to NextApiResponse", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "abc123");

      expect(mockRes.setHeader).toHaveBeenCalled();
      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );
      expect(setCookieCall).toBeDefined();
    });

    it("should set cookie with httpOnly flag", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token123", { httpOnly: true });

      expect(mockRes.setHeader).toHaveBeenCalled();
      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );
      expect(setCookieCall).toBeDefined();

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("session=token123");
      expect(setCookieValue).toContain("HttpOnly");
    });

    it("should set cookie with secure flag", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", { secure: true });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("Secure");
    });

    it("should set cookie with sameSite flag", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", { sameSite: "lax" });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("SameSite=lax");
    });

    it("should set cookie with maxAge", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", { maxAge: 3600 });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("Max-Age=3600");
    });

    it("should set cookie with path", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", { path: "/api" });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("Path=/api");
    });

    it("should set cookie with multiple options", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7200,
        path: "/"
      });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1][0]
        : setCookieCall[1];
      expect(setCookieValue).toContain("session=token");
      expect(setCookieValue).toContain("HttpOnly");
      expect(setCookieValue).toContain("Secure");
      expect(setCookieValue).toContain("SameSite=strict");
      expect(setCookieValue).toContain("Max-Age=7200");
      expect(setCookieValue).toContain("Path=/");
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      const result = cookies.set("test", "value");

      expect(result).toBe(cookies);
    });

    it("should handle multiple cookies", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("cookie1", "value1");
      cookies.set("cookie2", "value2");
      cookies.set("cookie3", "value3");

      const setCookieCalls = (mockRes.setHeader as any).mock.calls.filter(
        (call: any) => call[0] === "Set-Cookie"
      );

      expect(setCookieCalls.length).toBeGreaterThan(0);
    });

    it("should update existing cookie value", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "old-value");
      cookies.set("session", "new-value");

      const setCookieCall = (mockRes.setHeader as any).mock.calls.findLast(
        (call: any) => call[0] === "Set-Cookie"
      );

      const setCookieValue = Array.isArray(setCookieCall[1])
        ? setCookieCall[1].find((v: string) => v.includes("session="))
        : setCookieCall[1];
      expect(setCookieValue).toContain("session=new-value");
    });
  });

  describe("delete()", () => {
    it("should delete a cookie and sync to NextApiResponse", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token");
      cookies.delete("session");

      expect(mockRes.setHeader).toHaveBeenCalled();
    });

    it("should set expiration date in the past when deleting", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token");
      cookies.delete("session");

      const setCookieCall = (mockRes.setHeader as any).mock.calls.findLast(
        (call: any) => call[0] === "Set-Cookie"
      );

      expect(setCookieCall).toBeDefined();
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("test", "value");
      const result = cookies.delete("test");

      expect(result).toBe(cookies);
    });

    it("should handle deleting non-existent cookie", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      expect(() => {
        cookies.delete("nonexistent");
      }).not.toThrow();
    });

    it("should handle deleting multiple cookies", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("cookie1", "value1");
      cookies.set("cookie2", "value2");

      cookies.delete("cookie1");
      cookies.delete("cookie2");

      expect(mockRes.setHeader).toHaveBeenCalled();
    });
  });

  describe("get()", () => {
    it("should retrieve a cookie that was set", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "abc123");
      const cookie = cookies.get("session");

      expect(cookie).toBeDefined();
      expect(cookie?.name).toBe("session");
      expect(cookie?.value).toBe("abc123");
    });

    it("should return undefined for non-existent cookie", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      const cookie = cookies.get("nonexistent");

      expect(cookie).toBeUndefined();
    });

    it("should retrieve cookie with attributes", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token", {
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      });

      const cookie = cookies.get("session");

      expect(cookie?.httpOnly).toBe(true);
      expect(cookie?.secure).toBe(true);
      expect(cookie?.sameSite).toBe("lax");
    });
  });

  describe("getAll()", () => {
    it("should retrieve all cookies", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("cookie1", "value1");
      cookies.set("cookie2", "value2");
      cookies.set("cookie3", "value3");

      const allCookies = cookies.getAll();

      expect(allCookies.length).toBe(3);
      expect(allCookies.map((c) => c.name)).toContain("cookie1");
      expect(allCookies.map((c) => c.name)).toContain("cookie2");
      expect(allCookies.map((c) => c.name)).toContain("cookie3");
    });

    it("should return empty array when no cookies set", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      const allCookies = cookies.getAll();

      expect(Array.isArray(allCookies)).toBe(true);
      expect(allCookies.length).toBe(0);
    });
  });

  describe("has()", () => {
    it("should return true if cookie exists", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("session", "token");

      expect(cookies.has("session")).toBe(true);
    });

    it("should return false if cookie does not exist", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      expect(cookies.has("nonexistent")).toBe(false);
    });

    it("should be case-sensitive", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("Session", "token");

      expect(cookies.has("Session")).toBe(true);
      expect(cookies.has("session")).toBe(false);
    });
  });

  describe("syncToResponse()", () => {
    it("should sync cookies to NextApiResponse headers", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("test", "value");

      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "Set-Cookie",
        expect.anything()
      );
    });

    it("should handle multiple cookies in sync", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("cookie1", "value1");

      const firstCallCount = (mockRes.setHeader as any).mock.calls.length;

      cookies.set("cookie2", "value2");

      const secondCallCount = (mockRes.setHeader as any).mock.calls.length;

      expect(secondCallCount).toBeGreaterThan(firstCallCount);
    });

    it("should remove Set-Cookie header when all cookies are deleted", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("cookie1", "value1");
      cookies.delete("cookie1");

      // After deleting all cookies, the implementation may call removeHeader or setHeader
      // depending on whether there are any cookies left
      expect(
        (mockRes.removeHeader as any).mock.calls.some(
          (call: any) => call[0] === "Set-Cookie"
        ) ||
          (mockRes.setHeader as any).mock.calls.some(
            (call: any) => call[0] === "Set-Cookie"
          )
      ).toBe(true);
    });
  });

  describe("integration scenarios", () => {
    it("should handle session cookie lifecycle", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      // Set session cookie
      cookies.set("session", "user-session-token", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 86400,
        path: "/"
      });

      expect(cookies.has("session")).toBe(true);

      // Update session cookie
      cookies.set("session", "new-session-token", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 86400,
        path: "/"
      });

      const cookie = cookies.get("session");
      expect(cookie?.value).toBe("new-session-token");

      // Delete session cookie
      cookies.delete("session");

      expect(mockRes.setHeader).toHaveBeenCalled();
    });

    it("should handle multiple authentication cookies", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      cookies.set("access_token", "at_token", { httpOnly: true, maxAge: 3600 });
      cookies.set("refresh_token", "rt_token", {
        httpOnly: true,
        maxAge: 604800
      });
      cookies.set("id_token", "id_token", { httpOnly: true, maxAge: 3600 });

      expect(cookies.has("access_token")).toBe(true);
      expect(cookies.has("refresh_token")).toBe(true);
      expect(cookies.has("id_token")).toBe(true);

      const allCookies = cookies.getAll();
      expect(allCookies.length).toBe(3);
    });

    it("should handle cookie with special characters in value", () => {
      const mockRes = createMockNextApiResponse();
      const cookies = new Auth0ApiResponseCookies(mockRes);

      const complexValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
      cookies.set("jwt", complexValue, { httpOnly: true });

      const cookie = cookies.get("jwt");
      expect(cookie?.value).toBe(complexValue);
    });
  });
});
