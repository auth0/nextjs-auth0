import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetcher, Fetcher, fetchWithAuth } from "./fetcher.js";

describe("DPoP Fetcher", () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    // Reset global fetch mock
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Fetcher class", () => {
    it("should create a new fetcher instance with default config", () => {
      const fetcher = new Fetcher({});
      expect(fetcher).toBeDefined();
    });

    it("should create a new fetcher instance with custom config", () => {
      const customFetch = vi.fn();
      const fetcher = new Fetcher({
        baseUrl: "https://api.example.com",
        fetch: customFetch
      });
      expect(fetcher).toBeDefined();
    });

    it("should build protected request correctly for absolute URL", async () => {
      const mockResponse = new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});
      await fetcher.fetchWithAuth("https://api.example.com/data");

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];

      expect(url).toBe("/auth/protected-request");
      expect(options.method).toBe("POST");
      expect(options.headers["Content-Type"]).toBe("application/json");

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe("https://api.example.com/data");
      expect(requestBody.method).toBe("GET");
    });

    it("should build protected request correctly with baseUrl", async () => {
      const mockResponse = new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({
        baseUrl: "https://api.example.com"
      });
      await fetcher.fetchWithAuth("/data");

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe("https://api.example.com/data");
      expect(requestBody.method).toBe("GET");
    });

    it("should handle POST requests with body", async () => {
      const mockResponse = new Response(JSON.stringify({ created: true }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});
      const postData = { name: "test", value: 123 };

      await fetcher.fetchWithAuth("https://api.example.com/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(postData)
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe("https://api.example.com/create");
      expect(requestBody.method).toBe("POST");
      expect(requestBody.headers).toBeDefined();
      expect(requestBody.body).toBeDefined();
    });

    it("should handle custom headers", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});

      await fetcher.fetchWithAuth("https://api.example.com/data", {
        headers: {
          Authorization: "Bearer custom-token",
          "X-Custom-Header": "custom-value"
        }
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.headers).toBeDefined();
    });

    it("should use custom fetch implementation when provided", async () => {
      const customFetch = vi
        .fn()
        .mockResolvedValueOnce(
          new Response("Custom response", { status: 200 })
        );

      const fetcher = new Fetcher({
        fetch: customFetch
      });

      await fetcher.fetchWithAuth("https://api.example.com/data");

      expect(customFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("should handle URL objects", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});
      const urlObject = new URL("https://api.example.com/data");

      await fetcher.fetchWithAuth(urlObject);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe("https://api.example.com/data");
    });

    it("should handle Request objects", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});
      const request = new Request("https://api.example.com/data", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ update: true })
      });

      await fetcher.fetchWithAuth(request);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe("https://api.example.com/data");
      expect(requestBody.method).toBe("PUT");
    });

    it("should throw error for relative URL without baseUrl", () => {
      const fetcher = new Fetcher({});

      expect(() => {
        fetcher.fetchWithAuth("/data");
      }).toThrow("`url` must be absolute or `baseUrl` non-empty.");
    });
  });

  describe("createFetcher factory function", () => {
    it("should create a new fetcher instance with no config", () => {
      const fetcher = createFetcher();
      expect(fetcher).toBeInstanceOf(Fetcher);
    });

    it("should create a new fetcher instance with custom config", () => {
      const customFetch = vi.fn();
      const fetcher = createFetcher({
        baseUrl: "https://api.example.com",
        fetch: customFetch
      });
      expect(fetcher).toBeInstanceOf(Fetcher);
    });

    it("should create isolated fetcher instances", () => {
      const fetcher1 = createFetcher({ baseUrl: "https://api1.example.com" });
      const fetcher2 = createFetcher({ baseUrl: "https://api2.example.com" });

      expect(fetcher1).not.toBe(fetcher2);
    });
  });

  describe("fetchWithAuth convenience function", () => {
    it("should make authenticated requests using default fetcher", async () => {
      const mockResponse = new Response(JSON.stringify({ data: "test" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await fetchWithAuth("https://api.example.com/data");

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(result).toBe(mockResponse);

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe("/auth/protected-request");
      expect(options.method).toBe("POST");
    });

    it("should handle different HTTP methods", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      await fetchWithAuth("https://api.example.com/data", {
        method: "DELETE"
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.method).toBe("DELETE");
    });

    it("should propagate fetch errors", async () => {
      const fetchError = new Error("Network error");
      mockFetch.mockRejectedValueOnce(fetchError);

      await expect(
        fetchWithAuth("https://api.example.com/data")
      ).rejects.toThrow("Network error");
    });

    it("should return response for server errors", async () => {
      const errorResponse = new Response("Server Error", { status: 500 });
      mockFetch.mockResolvedValueOnce(errorResponse);

      const result = await fetchWithAuth("https://api.example.com/data");

      expect(result.status).toBe(500);
      expect(await result.text()).toBe("Server Error");
    });
  });

  describe("Environment variable support", () => {
    it("should use custom protected request route from environment", async () => {
      const originalEnv = process.env.NEXT_PUBLIC_PROTECTED_REQUEST_ROUTE;
      process.env.NEXT_PUBLIC_PROTECTED_REQUEST_ROUTE = "/custom/dpop-request";

      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const fetcher = new Fetcher({});
      await fetcher.fetchWithAuth("https://api.example.com/data");

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url] = mockFetch.mock.calls[0];
      expect(url).toBe("/custom/dpop-request");

      // Restore original environment
      if (originalEnv) {
        process.env.NEXT_PUBLIC_PROTECTED_REQUEST_ROUTE = originalEnv;
      } else {
        delete process.env.NEXT_PUBLIC_PROTECTED_REQUEST_ROUTE;
      }
    });
  });

  describe("Edge cases", () => {
    it("should handle empty response body", async () => {
      const mockResponse = new Response(null, { status: 204 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await fetchWithAuth("https://api.example.com/data");

      expect(result.status).toBe(204);
      expect(result.body).toBeNull();
    });

    it("should handle large request bodies", async () => {
      const largeData = "x".repeat(1024 * 1024); // 1MB string
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      await fetchWithAuth("https://api.example.com/upload", {
        method: "POST",
        body: largeData
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.body).toBeDefined();
    });

    it("should handle special characters in URLs", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValueOnce(mockResponse);

      await fetchWithAuth(
        "https://api.example.com/search?q=test%20data&sort=asc"
      );

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [_url, options] = mockFetch.mock.calls[0];

      const requestBody = JSON.parse(options.body);
      expect(requestBody.url).toBe(
        "https://api.example.com/search?q=test%20data&sort=asc"
      );
    });
  });
});
