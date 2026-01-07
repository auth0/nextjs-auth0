import { NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";
import { Auth0NextResponse } from "./auth0-next-response.js";

describe("Auth0NextResponse", () => {
  describe("getCookies()", () => {
    it("should return Auth0ResponseCookies object", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      const cookies = auth0Response.getCookies();

      expect(cookies).toBeDefined();
      expect(typeof cookies.get).toBe("function");
      expect(typeof cookies.set).toBe("function");
      expect(typeof cookies.delete).toBe("function");
    });

    it("should allow setting cookies", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      const cookies = auth0Response.getCookies();
      expect(() => {
        cookies.set("session", "token123", {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/"
        });
      }).not.toThrow();
    });
  });

  describe("redirect()", () => {
    it("should set redirect location header", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.redirect("https://example.com/callback");

      expect(auth0Response.res.status).toBe(307);
      expect(auth0Response.res.headers.get("location")).toBe("https://example.com/callback");
    });

    it("should preserve headers from previous response", () => {
      const response = new NextResponse(null, {
        headers: { "x-custom": "value" }
      });
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.redirect("https://example.com/redirect");

      expect(auth0Response.res.headers.get("x-custom")).toBe("value");
      expect(auth0Response.res.headers.get("location")).toBe("https://example.com/redirect");
    });
  });

  describe("status()", () => {
    it("should set status code", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.status("Unauthorized", 401);

      expect(auth0Response.res.status).toBe(401);
    });

    it("should set response body with status", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.status("Not Found", 404);

      expect(auth0Response.res.status).toBe(404);
    });

    it("should handle null message", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.status(null, 500);

      expect(auth0Response.res.status).toBe(500);
    });

    it("should support various HTTP status codes", () => {
      const codes = [200, 201, 204, 400, 401, 403, 404, 500, 502, 503];

      codes.forEach((code) => {
        const response = NextResponse.next();
        const auth0Response = new Auth0NextResponse(response);

        auth0Response.status("message", code);

        expect(auth0Response.res.status).toBe(code);
      });
    });
  });

  describe("json()", () => {
    it("should create JSON response", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      const data = { token: "abc123", user: { id: 1 } };
      auth0Response.json(data);

      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
    });

    it("should set status code when provided in init", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.json({ error: "Unauthorized" }, { status: 401 });

      expect(auth0Response.res.status).toBe(401);
    });

    it("should handle empty object", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.json({});

      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
    });

    it("should handle nested objects", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      const data = {
        user: {
          profile: {
            name: "John",
            email: "john@example.com"
          }
        }
      };
      auth0Response.json(data);

      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
    });

    it("should preserve previous headers", () => {
      const response = new NextResponse(null, {
        headers: { "x-custom": "value" }
      });
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.json({ data: "test" });

      expect(auth0Response.res.headers.get("x-custom")).toBe("value");
      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
    });
  });

  describe("setResponse()", () => {
    it("should replace response with new response", () => {
      const oldResponse = new NextResponse("old body");
      const auth0Response = new Auth0NextResponse(oldResponse);

      const newResponse = new NextResponse("new body", { status: 201 });
      auth0Response.setResponse(newResponse);

      expect(auth0Response.res).toBe(newResponse);
    });

    it("should preserve headers from old response", () => {
      const oldResponse = new NextResponse("old", {
        headers: { "x-old": "value" }
      });
      const auth0Response = new Auth0NextResponse(oldResponse);

      const newResponse = new NextResponse("new");
      auth0Response.setResponse(newResponse);

      expect(auth0Response.res.headers.get("x-old")).toBe("value");
    });
  });

  describe("addCacheControlHeadersForSession()", () => {
    it("should set Cache-Control header", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.addCacheControlHeadersForSession();

      const cacheControl = auth0Response.res.headers.get("cache-control");
      expect(cacheControl).toContain("no-cache");
      expect(cacheControl).toContain("no-store");
      expect(cacheControl).toContain("must-revalidate");
      expect(cacheControl).toContain("private");
    });

    it("should set Pragma header", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.addCacheControlHeadersForSession();

      expect(auth0Response.res.headers.get("pragma")).toBe("no-cache");
    });

    it("should set Expires header", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.addCacheControlHeadersForSession();

      expect(auth0Response.res.headers.get("expires")).toBe("0");
    });

    it("should prevent all forms of caching", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.addCacheControlHeadersForSession();

      const cacheControl = auth0Response.res.headers.get("cache-control")!;
      expect(cacheControl).toContain("max-age=0");
      expect(cacheControl).toContain("must-revalidate");
    });
  });

  describe("header merging", () => {
    it("should merge custom headers when creating new response", () => {
      const oldResponse = new NextResponse(null, {
        headers: { "x-custom": "preserved", "x-another": "value" }
      });
      const auth0Response = new Auth0NextResponse(oldResponse);

      auth0Response.json({ data: "test" });

      expect(auth0Response.res.headers.get("x-custom")).toBe("preserved");
      expect(auth0Response.res.headers.get("x-another")).toBe("value");
    });

    it("should handle security headers correctly", () => {
      const oldResponse = new NextResponse(null, {
        headers: {
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY"
        }
      });
      const auth0Response = new Auth0NextResponse(oldResponse);

      auth0Response.json({ data: "test" });

      expect(auth0Response.res.headers.get("content-security-policy")).toBe("default-src 'self'");
      expect(auth0Response.res.headers.get("x-frame-options")).toBe("DENY");
    });
  });

  describe("constructor", () => {
    it("should store the underlying NextResponse", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      expect(auth0Response.res).toBe(response);
    });
  });

  describe("integration scenarios", () => {
    it("should handle successful login response", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.json({
        user: { id: "123", email: "user@example.com" },
        token: "jwt_token"
      });
      auth0Response.addCacheControlHeadersForSession();
      auth0Response.getCookies().set("session", "session_token", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/"
      });

      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
      expect(auth0Response.res.headers.get("cache-control")).toContain("no-store");
    });

    it("should handle error response", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.json(
        { error: "invalid_grant", error_description: "Invalid credentials" },
        { status: 401 }
      );

      expect(auth0Response.res.status).toBe(401);
      expect(auth0Response.res.headers.get("content-type")).toContain("application/json");
    });

    it("should handle redirect after login", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.redirect("https://example.com/dashboard");
      auth0Response.getCookies().set("session", "token", {
        httpOnly: true,
        secure: true,
        path: "/"
      });

      expect(auth0Response.res.status).toBe(307);
      expect(auth0Response.res.headers.get("location")).toBe("https://example.com/dashboard");
    });

    it("should handle logout response", () => {
      const response = NextResponse.next();
      const auth0Response = new Auth0NextResponse(response);

      auth0Response.getCookies().delete("session");
      auth0Response.redirect("https://example.com");

      expect(auth0Response.res.headers.get("location")).toBe("https://example.com/");
    });
  });
});
