import { NextApiRequest } from "next";
import { describe, expect, it, beforeEach, afterEach } from "vitest";

import { Auth0NextApiRequest } from "./auth0-next-api-request.js";

/**
 * Creates a mock NextApiRequest for testing
 */
function createMockNextApiRequest(
  url: string,
  options: {
    method?: string;
    body?: any;
    cookies?: Record<string, string>;
    headers?: Record<string, string>;
  } = {}
): NextApiRequest {
  const urlObj = new URL(url);
  const { method = "GET", body = {}, cookies = {}, headers = {} } = options;

  return {
    method,
    url: urlObj.pathname + urlObj.search,
    headers: {
      host: urlObj.host,
      ...headers
    },
    body,
    cookies,
    query: Object.fromEntries(urlObj.searchParams.entries())
  } as NextApiRequest;
}

describe("Auth0NextApiRequest", () => {
  const originalAppBaseUrl = process.env.APP_BASE_URL;

  beforeEach(() => {
    process.env.APP_BASE_URL = "https://example.com";
  });

  afterEach(() => {
    process.env.APP_BASE_URL = originalAppBaseUrl;
  });

  describe("getUrl()", () => {
    it("should return the request URL", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login"
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url).toBeInstanceOf(URL);
      expect(url.href).toContain("example.com");
      expect(url.pathname).toBe("/api/auth/login");
    });

    it("should construct URL using APP_BASE_URL environment variable", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/callback"
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url.href).toBe("https://example.com/api/auth/callback");
    });

    it("should include query parameters in the URL", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login?returnTo=/dashboard"
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("returnTo")).toBe("/dashboard");
    });

    it("should handle complex URLs with multiple query parameters", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/callback?code=abc123&state=xyz789"
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("code")).toBe("abc123");
      expect(url.searchParams.get("state")).toBe("xyz789");
    });

    it("should handle URLs with encoded characters", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login?email=user%40example.com"
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("email")).toBe("user@example.com");
    });
  });

  describe("getMethod()", () => {
    it("should return the HTTP method for GET requests", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "GET"
      });
      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.getMethod()).toBe("GET");
    });

    it("should return the HTTP method for POST requests", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST"
      });
      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.getMethod()).toBe("POST");
    });

    it("should return the HTTP method for other HTTP methods", () => {
      const methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

      methods.forEach((method) => {
        const mockReq = createMockNextApiRequest(
          "https://example.com/api/test",
          { method }
        );
        const auth0Request = new Auth0NextApiRequest(mockReq);

        expect(auth0Request.getMethod()).toBe(method);
      });
    });

    it("should handle lowercase method names", () => {
      const mockReq = {
        method: "get",
        url: "/api/test",
        headers: {},
        body: {},
        cookies: {},
        query: {}
      } as NextApiRequest;

      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.getMethod()).toBe("get");
    });
  });

  describe("getBody()", () => {
    it("should return the request body as an object", () => {
      const body = { username: "test", password: "secret" };
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST",
        body
      });
      const auth0Request = new Auth0NextApiRequest(mockReq);

      const requestBody = auth0Request.getBody();

      expect(requestBody).toEqual(body);
    });

    it("should return the request body for JSON content", () => {
      const jsonBody = { key: "value", nested: { prop: "data" } };
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST",
        body: jsonBody,
        headers: { "content-type": "application/json" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const body = auth0Request.getBody();

      expect(body).toEqual(jsonBody);
    });

    it("should return the request body for form data", () => {
      const formData = {
        username: "user@example.com",
        password: "secret"
      };

      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST",
        body: formData,
        headers: { "content-type": "application/x-www-form-urlencoded" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const body = auth0Request.getBody();

      expect(body).toEqual(formData);
    });

    it("should return empty object for requests with no body", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "GET"
      });
      const auth0Request = new Auth0NextApiRequest(mockReq);

      const body = auth0Request.getBody();

      expect(body).toEqual({});
    });

    it("should handle complex nested objects in body", () => {
      const complexBody = {
        user: {
          name: "John Doe",
          email: "john@example.com",
          preferences: {
            theme: "dark",
            notifications: true
          }
        },
        metadata: {
          timestamp: "2024-01-01",
          source: "web"
        }
      };

      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST",
        body: complexBody
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const body = auth0Request.getBody();

      expect(body).toEqual(complexBody);
    });
  });

  describe("getHeaders()", () => {
    it("should return the request headers", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        headers: {
          "content-type": "application/json",
          authorization: "Bearer token123"
        }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const headers = auth0Request.getHeaders();

      expect(headers).toBeInstanceOf(Headers);
      expect(headers.get("content-type")).toBe("application/json");
      expect(headers.get("authorization")).toBe("Bearer token123");
    });

    it("should be case-insensitive for header names", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        headers: { "Content-Type": "text/html" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const headers = auth0Request.getHeaders();

      expect(headers.get("content-type")).toBe("text/html");
      expect(headers.get("Content-Type")).toBe("text/html");
      expect(headers.get("CONTENT-TYPE")).toBe("text/html");
    });

    it("should include custom headers", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        headers: {
          "x-custom-header": "custom-value",
          "x-another-header": "another-value"
        }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const headers = auth0Request.getHeaders();

      expect(headers.get("x-custom-header")).toBe("custom-value");
      expect(headers.get("x-another-header")).toBe("another-value");
    });

    it("should include host header from request", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test");

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const headers = auth0Request.getHeaders();

      expect(headers.get("host")).toBe("example.com");
    });

    it("should handle empty headers", () => {
      const mockReq = {
        method: "GET",
        url: "/api/test",
        headers: {},
        body: {},
        cookies: {},
        query: {}
      } as NextApiRequest;

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const headers = auth0Request.getHeaders();

      expect(headers).toBeInstanceOf(Headers);
    });
  });

  describe("clone()", () => {
    it("should return the original request", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        method: "POST",
        body: { test: "data" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const clonedRequest = auth0Request.clone();

      expect(clonedRequest).toBe(mockReq);
    });

    it("should preserve request properties", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/test",
        {
          method: "POST",
          headers: { "x-test": "value" },
          body: { key: "value" }
        }
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const clonedRequest = auth0Request.clone();

      expect(clonedRequest.method).toBe("POST");
      expect(clonedRequest.headers["x-test"]).toBe("value");
      expect(clonedRequest.body).toEqual({ key: "value" });
    });
  });

  describe("getCookies()", () => {
    it("should return Auth0RequestCookies object", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        cookies: { session: "abc123", preferences: "dark" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      expect(cookies).toBeDefined();
      expect(typeof cookies.get).toBe("function");
      expect(typeof cookies.getAll).toBe("function");
      expect(typeof cookies.has).toBe("function");
    });

    it("should provide access to cookies from request", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        cookies: { session: "abc123", "auth-token": "xyz789" }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      expect(cookies.get("session")?.value).toBe("abc123");
      expect(cookies.get("auth-token")?.value).toBe("xyz789");
      expect(cookies.has("session")).toBe(true);
      expect(cookies.has("auth-token")).toBe(true);
    });

    it("should handle requests with no cookies", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        cookies: {}
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      expect(cookies.getAll()).toEqual([]);
      expect(cookies.has("nonexistent")).toBe(false);
    });

    it("should handle cookies with special characters", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        cookies: {
          "session-token": "abc123",
          user_id: "12345"
        }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      expect(cookies.get("session-token")?.value).toBe("abc123");
      expect(cookies.get("user_id")?.value).toBe("12345");
    });

    it("should handle multiple cookies", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test", {
        cookies: {
          cookie1: "value1",
          cookie2: "value2",
          cookie3: "value3"
        }
      });

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      const allCookies = cookies.getAll();
      expect(allCookies.length).toBe(3);
    });
  });

  describe("constructor", () => {
    it("should store the underlying NextApiRequest", () => {
      const mockReq = createMockNextApiRequest("https://example.com/api/test");
      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.req).toBe(mockReq);
    });

    it("should accept NextApiRequest as constructor argument", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login",
        {
          method: "GET"
        }
      );

      expect(() => {
        new Auth0NextApiRequest(mockReq);
      }).not.toThrow();
    });
  });

  describe("integration scenarios", () => {
    it("should handle OAuth callback scenario", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/callback?code=auth0_code&state=random_state",
        { method: "GET" }
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.getMethod()).toBe("GET");
      const url = auth0Request.getUrl();
      expect(url.searchParams.get("code")).toBe("auth0_code");
      expect(url.searchParams.get("state")).toBe("random_state");
    });

    it("should handle login form submission scenario", () => {
      const formBody = {
        email: "user@example.com",
        password: "secret123"
      };

      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login",
        {
          method: "POST",
          body: formBody,
          headers: { "content-type": "application/x-www-form-urlencoded" }
        }
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);

      expect(auth0Request.getMethod()).toBe("POST");
      const body = auth0Request.getBody();
      expect(body).toEqual(formBody);
    });

    it("should handle logout with session cookie scenario", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/logout",
        {
          method: "GET",
          cookies: { session: "user_session_token", auth0_id: "user123" }
        }
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const cookies = auth0Request.getCookies();

      expect(cookies.has("session")).toBe(true);
      expect(cookies.has("auth0_id")).toBe(true);
    });

    it("should handle API route with organization parameter", () => {
      const mockReq = createMockNextApiRequest(
        "https://example.com/api/auth/login?organization=org_123",
        { method: "GET" }
      );

      const auth0Request = new Auth0NextApiRequest(mockReq);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("organization")).toBe("org_123");
    });
  });
});
