import { NextRequest } from "next/server.js";
import { describe, expect, it } from "vitest";
import { Auth0NextRequest } from "./auth0-next-request.js";

describe("Auth0NextRequest", () => {
  describe("getUrl()", () => {
    it("should return the request URL", () => {
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });

      const auth0Request = new Auth0NextRequest(request);
      const url = auth0Request.getUrl();

      expect(url).toBeInstanceOf(URL);
      expect(url.href).toContain("example.com");
      expect(url.pathname).toBe("/auth/login");
    });

    it("should use nextUrl instead of url to support middleware rewrites", () => {
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });

      const auth0Request = new Auth0NextRequest(request);
      const url = auth0Request.getUrl();

      // nextUrl is the rewritten URL in middleware context - should have same href
      expect(url.href).toBe(request.nextUrl.href);
    });

    it("should include query parameters in the URL", () => {
      const request = new NextRequest("https://example.com/auth/login?returnTo=/dashboard", {
        method: "GET"
      });

      const auth0Request = new Auth0NextRequest(request);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("returnTo")).toBe("/dashboard");
    });

    it("should handle complex URLs with fragments and special characters", () => {
      const request = new NextRequest("https://example.com/auth/callback?code=abc123&state=xyz789", {
        method: "GET"
      });

      const auth0Request = new Auth0NextRequest(request);
      const url = auth0Request.getUrl();

      expect(url.searchParams.get("code")).toBe("abc123");
      expect(url.searchParams.get("state")).toBe("xyz789");
    });
  });

  describe("getMethod()", () => {
    it("should return the HTTP method for GET requests", () => {
      const request = new NextRequest("https://example.com", { method: "GET" });
      const auth0Request = new Auth0NextRequest(request);

      expect(auth0Request.getMethod()).toBe("GET");
    });

    it("should return the HTTP method for POST requests", () => {
      const request = new NextRequest("https://example.com", { method: "POST" });
      const auth0Request = new Auth0NextRequest(request);

      expect(auth0Request.getMethod()).toBe("POST");
    });

    it("should return the HTTP method for other HTTP methods", () => {
      const methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

      methods.forEach((method) => {
        const request = new NextRequest("https://example.com", { method });
        const auth0Request = new Auth0NextRequest(request);

        expect(auth0Request.getMethod()).toBe(method);
      });
    });
  });

  describe("getBody()", () => {
    it("should return the request body as text", async () => {
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: "test body content"
      });

      const auth0Request = new Auth0NextRequest(request);
      const body = await auth0Request.getBody();

      expect(body).toBe("test body content");
    });

    it("should return the request body for JSON content", async () => {
      const jsonBody = { key: "value" };
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: JSON.stringify(jsonBody),
        headers: { "content-type": "application/json" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const body = await auth0Request.getBody();

      expect(body).toEqual(JSON.stringify(jsonBody));
    });

    it("should return the request body for form data", async () => {
      const formData = new URLSearchParams({
        username: "user@example.com",
        password: "secret"
      }).toString();

      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: formData,
        headers: { "content-type": "application/x-www-form-urlencoded" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const body = await auth0Request.getBody();

      expect(body).toContain("username=user%40example.com");
      expect(body).toContain("password=secret");
    });

    it("should return empty string for requests with no body", async () => {
      const request = new NextRequest("https://example.com", { method: "GET" });
      const auth0Request = new Auth0NextRequest(request);

      const body = await auth0Request.getBody();

      expect(body).toBe("");
    });

    it("should handle large request bodies", async () => {
      const largeBody = "x".repeat(10000);
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: largeBody
      });

      const auth0Request = new Auth0NextRequest(request);
      const body = await auth0Request.getBody();

      expect(body).toBe(largeBody);
      expect(body.length).toBe(10000);
    });

    it("should return a promise", () => {
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: "test"
      });

      const auth0Request = new Auth0NextRequest(request);
      const bodyPromise = auth0Request.getBody();

      expect(bodyPromise instanceof Promise).toBe(true);
    });
  });

  describe("getHeaders()", () => {
    it("should return the request headers", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          "content-type": "application/json",
          "authorization": "Bearer token123"
        }
      });

      const auth0Request = new Auth0NextRequest(request);
      const headers = auth0Request.getHeaders();

      expect(headers).toBeInstanceOf(Headers);
      expect(headers.get("content-type")).toBe("application/json");
      expect(headers.get("authorization")).toBe("Bearer token123");
    });

    it("should be case-insensitive for header names", () => {
      const request = new NextRequest("https://example.com", {
        headers: { "Content-Type": "text/html" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const headers = auth0Request.getHeaders();

      expect(headers.get("content-type")).toBe("text/html");
      expect(headers.get("Content-Type")).toBe("text/html");
      expect(headers.get("CONTENT-TYPE")).toBe("text/html");
    });

    it("should handle multiple header values", () => {
      const request = new NextRequest("https://example.com", {
        headers: { "accept": "application/json, text/plain" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const headers = auth0Request.getHeaders();

      expect(headers.get("accept")).toContain("application/json");
      expect(headers.get("accept")).toContain("text/plain");
    });

    it("should include custom headers", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          "x-custom-header": "custom-value",
          "x-another-header": "another-value"
        }
      });

      const auth0Request = new Auth0NextRequest(request);
      const headers = auth0Request.getHeaders();

      expect(headers.get("x-custom-header")).toBe("custom-value");
      expect(headers.get("x-another-header")).toBe("another-value");
    });
  });

  describe("clone()", () => {
    it("should clone the request", () => {
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: "test body"
      });

      const auth0Request = new Auth0NextRequest(request);
      const clonedRequest = auth0Request.clone();

      expect(clonedRequest).not.toBe(request);
      expect(clonedRequest).toBeInstanceOf(Request);
    });

    it("should allow reading body from cloned request", async () => {
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: "test body"
      });

      const auth0Request = new Auth0NextRequest(request);
      const clonedRequest = auth0Request.clone();

      const body = await clonedRequest.text();
      expect(body).toBe("test body");
    });

    it("should preserve request properties in cloned request", () => {
      const request = new NextRequest("https://example.com/test", {
        method: "POST",
        headers: { "x-test": "value" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const clonedRequest = auth0Request.clone();

      expect(clonedRequest.method).toBe("POST");
      expect(clonedRequest.headers.get("x-test")).toBe("value");
    });

    it("should create independent clones", async () => {
      const request = new NextRequest("https://example.com", {
        method: "POST",
        body: "original body"
      });

      const auth0Request = new Auth0NextRequest(request);
      const cloned1 = auth0Request.clone();
      const cloned2 = auth0Request.clone();

      const body1 = await cloned1.text();
      const body2 = await cloned2.text();

      expect(body1).toBe("original body");
      expect(body2).toBe("original body");
      expect(cloned1).not.toBe(cloned2);
    });
  });

  describe("getCookies()", () => {
    it("should return Auth0RequestCookies object", () => {
      const request = new NextRequest("https://example.com", {
        headers: { cookie: "session=abc123; preferences=dark" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const cookies = auth0Request.getCookies();

      expect(cookies).toBeDefined();
      expect(typeof cookies.get).toBe("function");
      expect(typeof cookies.getAll).toBe("function");
      expect(typeof cookies.has).toBe("function");
    });

    it("should provide access to cookies from request", () => {
      const request = new NextRequest("https://example.com", {
        headers: { cookie: "session=abc123" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const cookies = auth0Request.getCookies();

      expect(cookies.has("session")).toBe(true);
    });

    it("should handle requests with no cookies", () => {
      const request = new NextRequest("https://example.com");

      const auth0Request = new Auth0NextRequest(request);
      const cookies = auth0Request.getCookies();

      expect(cookies.getAll()).toEqual([]);
    });
  });

  describe("constructor", () => {
    it("should store the underlying NextRequest", () => {
      const request = new NextRequest("https://example.com");
      const auth0Request = new Auth0NextRequest(request);

      expect(auth0Request.req).toBe(request);
    });

    it("should accept NextRequest as constructor argument", () => {
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });

      expect(() => {
        new Auth0NextRequest(request);
      }).not.toThrow();
    });
  });

  describe("integration scenarios", () => {
    it("should handle OAuth callback scenario", async () => {
      const request = new NextRequest(
        "https://example.com/auth/callback?code=auth0_code&state=random_state",
        { method: "GET" }
      );

      const auth0Request = new Auth0NextRequest(request);

      expect(auth0Request.getMethod()).toBe("GET");
      const url = auth0Request.getUrl();
      expect(url.searchParams.get("code")).toBe("auth0_code");
      expect(url.searchParams.get("state")).toBe("random_state");
    });

    it("should handle login form submission scenario", async () => {
      const formBody = new URLSearchParams({
        email: "user@example.com",
        password: "secret123"
      }).toString();

      const request = new NextRequest("https://example.com/auth/login", {
        method: "POST",
        body: formBody,
        headers: { "content-type": "application/x-www-form-urlencoded" }
      });

      const auth0Request = new Auth0NextRequest(request);

      expect(auth0Request.getMethod()).toBe("POST");
      const body = await auth0Request.getBody();
      expect(body).toContain("email=user%40example.com");
    });

    it("should handle logout with session cookie scenario", () => {
      const request = new NextRequest("https://example.com/auth/logout", {
        method: "GET",
        headers: { cookie: "session=user_session_token; auth0_id=user123" }
      });

      const auth0Request = new Auth0NextRequest(request);
      const cookies = auth0Request.getCookies();

      expect(cookies.has("session")).toBe(true);
      expect(cookies.has("auth0_id")).toBe(true);
    });
  });
});
