import { NextApiResponse } from "next";
import { describe, expect, it, vi } from "vitest";

import { Auth0NextApiResponse } from "./auth0-next-api-response.js";

/**
 * Creates a mock NextApiResponse for testing
 */
function createMockNextApiResponse(): NextApiResponse {
  const headers: Record<string, string | string[]> = {};
  let statusCode = 200;
  let statusMessage = "OK";
  const writtenData: any[] = [];

  const res = {
    statusCode,
    statusMessage,
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
    status: vi.fn((code: number) => {
      statusCode = code;
      res.statusCode = code;
      return res;
    }),
    redirect: vi.fn((url: string) => {
      res.setHeader("Location", url);
      res.status(302);
      return res;
    }),
    json: vi.fn((data: any) => {
      res.setHeader("Content-Type", "application/json");
      writtenData.push(JSON.stringify(data));
      return res;
    }),
    send: vi.fn((data: any) => {
      writtenData.push(data);
      return res;
    }),
    end: vi.fn(() => res),
    // Add a getter to access written data for testing
    _getWrittenData: () => writtenData
  } as unknown as NextApiResponse & { _getWrittenData: () => any[] };

  return res;
}

describe("Auth0NextApiResponse", () => {
  describe("getCookies()", () => {
    it("should return Auth0ApiResponseCookies object", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const cookies = auth0Response.getCookies();

      expect(cookies).toBeDefined();
      expect(typeof cookies.get).toBe("function");
      expect(typeof cookies.set).toBe("function");
      expect(typeof cookies.delete).toBe("function");
    });

    it("should allow setting cookies", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const cookies = auth0Response.getCookies();
      expect(() => {
        cookies.set("session", "token123", {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/"
        });
      }).not.toThrow();

      expect(mockRes.setHeader).toHaveBeenCalled();
    });

    it("should sync cookie changes to NextApiResponse", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const cookies = auth0Response.getCookies();
      cookies.set("test-cookie", "test-value", {
        maxAge: 3600,
        httpOnly: true
      });

      const setCookieCall = (mockRes.setHeader as any).mock.calls.find(
        (call: any) => call[0] === "Set-Cookie"
      );
      expect(setCookieCall).toBeDefined();
    });
  });

  describe("redirect()", () => {
    it("should set redirect location header", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.redirect("https://example.com/callback");

      expect(mockRes.redirect).toHaveBeenCalledWith(
        "https://example.com/callback"
      );
      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "Location",
        "https://example.com/callback"
      );
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const result = auth0Response.redirect("https://example.com/redirect");

      expect(result).toBe(auth0Response);
    });

    it("should handle Auth0 authorization URLs", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const authUrl =
        "https://test.auth0.com/authorize?client_id=test&redirect_uri=http://localhost/callback";
      auth0Response.redirect(authUrl);

      expect(mockRes.redirect).toHaveBeenCalledWith(authUrl);
    });

    it("should handle relative URLs", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.redirect("/dashboard");

      expect(mockRes.redirect).toHaveBeenCalledWith("/dashboard");
    });
  });

  describe("status()", () => {
    it("should set status code and send message", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.status("Unauthorized", 401);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.send).toHaveBeenCalledWith("Unauthorized");
    });

    it("should handle null message", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.status(null, 500);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith(null);
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const result = auth0Response.status("OK", 200);

      expect(result).toBe(auth0Response);
    });

    it("should support various HTTP status codes", () => {
      const codes = [200, 201, 204, 400, 401, 403, 404, 500, 502, 503];

      codes.forEach((code) => {
        const mockRes = createMockNextApiResponse();
        const auth0Response = new Auth0NextApiResponse(mockRes);

        auth0Response.status("message", code);

        expect(mockRes.status).toHaveBeenCalledWith(code);
      });
    });

    it("should send error messages", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.status("Internal Server Error", 500);

      expect(mockRes.send).toHaveBeenCalledWith("Internal Server Error");
    });
  });

  describe("json()", () => {
    it("should send JSON response", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const data = { token: "abc123", user: { id: 1 } };
      auth0Response.json(data);

      expect(mockRes.json).toHaveBeenCalledWith(data);
    });

    it("should set status code when provided in init", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.json({ error: "Unauthorized" }, { status: 401 });

      expect(mockRes.statusCode).toBe(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: "Unauthorized" });
    });

    it("should set custom headers when provided in init", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.json(
        { data: "test" },
        {
          headers: { "X-Custom-Header": "test-value" }
        }
      );

      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "X-Custom-Header",
        "test-value"
      );
    });

    it("should handle empty object", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.json({});

      expect(mockRes.json).toHaveBeenCalledWith({});
    });

    it("should handle nested objects", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const data = {
        user: {
          profile: {
            name: "John",
            email: "john@example.com"
          }
        }
      };
      auth0Response.json(data);

      expect(mockRes.json).toHaveBeenCalledWith(data);
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const result = auth0Response.json({ test: "data" });

      expect(result).toBe(auth0Response);
    });

    it("should handle arrays", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const data = [{ id: 1 }, { id: 2 }, { id: 3 }];
      auth0Response.json(data);

      expect(mockRes.json).toHaveBeenCalledWith(data);
    });
  });

  describe("addCacheControlHeadersForSession()", () => {
    it("should add cache control headers", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.addCacheControlHeadersForSession();

      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "Cache-Control",
        expect.any(String)
      );
      expect(mockRes.setHeader).toHaveBeenCalledWith("Pragma", "no-cache");
      expect(mockRes.setHeader).toHaveBeenCalledWith("Expires", "0");
    });

    it("should prevent caching with appropriate headers", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.addCacheControlHeadersForSession();

      const calls = (mockRes.setHeader as any).mock.calls;
      const cacheControlCalls = calls.filter(
        (call: any) => call[0] === "Cache-Control"
      );

      expect(cacheControlCalls.length).toBeGreaterThan(0);
      expect(cacheControlCalls.some((call: any) => call[1] === "no-store")).toBe(
        true
      );
    });
  });

  describe("setResponse()", () => {
    it("should update the internal response object", () => {
      const mockRes1 = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes1);

      const mockRes2 = createMockNextApiResponse();
      auth0Response.setResponse(mockRes2);

      expect(auth0Response.res).toBe(mockRes2);
    });

    it("should allow changing response mid-processing", () => {
      const mockRes1 = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes1);

      const mockRes2 = createMockNextApiResponse();
      auth0Response.setResponse(mockRes2);

      auth0Response.status("OK", 200);

      expect(mockRes2.status).toHaveBeenCalledWith(200);
      expect(mockRes1.status).not.toHaveBeenCalled();
    });
  });

  describe("generic()", () => {
    it("should send generic response with body and init", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.generic("Response body", {
        status: 201,
        statusText: "Created",
        headers: { "Content-Type": "text/plain" }
      });

      expect(mockRes.statusCode).toBe(201);
      expect(mockRes.statusMessage).toBe("Created");
      expect(mockRes.setHeader).toHaveBeenCalledWith("Content-Type", "text/plain");
      expect(mockRes.send).toHaveBeenCalledWith("Response body");
    });

    it("should handle null body", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.generic(null, {
        status: 204
      });

      expect(mockRes.statusCode).toBe(204);
      expect(mockRes.send).toHaveBeenCalledWith(null);
    });

    it("should apply multiple headers", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.generic("body", {
        status: 200,
        headers: {
          "X-Custom-1": "value1",
          "X-Custom-2": "value2"
        }
      });

      expect(mockRes.setHeader).toHaveBeenCalledWith("X-Custom-1", "value1");
      expect(mockRes.setHeader).toHaveBeenCalledWith("X-Custom-2", "value2");
    });

    it("should return this for method chaining", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const result = auth0Response.generic("test", { status: 200 });

      expect(result).toBe(auth0Response);
    });
  });

  describe("constructor", () => {
    it("should store the underlying NextApiResponse", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      expect(auth0Response.res).toBe(mockRes);
    });

    it("should accept NextApiResponse as constructor argument", () => {
      const mockRes = createMockNextApiResponse();

      expect(() => {
        new Auth0NextApiResponse(mockRes);
      }).not.toThrow();
    });
  });

  describe("integration scenarios", () => {
    it("should handle OAuth callback success", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.redirect("/dashboard");

      expect(mockRes.redirect).toHaveBeenCalledWith("/dashboard");
    });

    it("should handle authentication error", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      auth0Response.json(
        { error: "invalid_grant", error_description: "Invalid credentials" },
        { status: 401 }
      );

      expect(mockRes.statusCode).toBe(401);
      expect(mockRes.json).toHaveBeenCalled();
    });

    it("should handle logout flow", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const cookies = auth0Response.getCookies();
      cookies.delete("session");

      auth0Response.redirect("https://auth0.com/v2/logout");

      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it("should handle user info response", () => {
      const mockRes = createMockNextApiResponse();
      const auth0Response = new Auth0NextApiResponse(mockRes);

      const userInfo = {
        sub: "auth0|123",
        name: "John Doe",
        email: "john@example.com"
      };

      auth0Response.json(userInfo);
      auth0Response.addCacheControlHeadersForSession();

      expect(mockRes.json).toHaveBeenCalledWith(userInfo);
      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "Cache-Control",
        expect.any(String)
      );
    });
  });
});
