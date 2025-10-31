import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server.js";
import {
  buildForwardedRequestHeaders,
  buildForwardedResponseHeaders,
} from "./proxy.js";

describe("headers", () => {
  describe("buildForwardedRequestHeaders", () => {
    it("should forward headers from the default allow-list", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          accept: "application/json",
          "accept-language": "en-US",
          "user-agent": "Mozilla/5.0",
          "x-forwarded-for": "192.168.1.1",
          "x-request-id": "abc123",
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("accept")).toBe("application/json");
      expect(result.get("accept-language")).toBe("en-US");
      expect(result.get("user-agent")).toBe("Mozilla/5.0");
      expect(result.get("x-forwarded-for")).toBe("192.168.1.1");
      expect(result.get("x-request-id")).toBe("abc123");
    });

    it("should not forward headers not in the allow-list", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          accept: "application/json",
          "x-custom-header": "should-not-be-forwarded",
          authorization: "Bearer token",
          cookie: "session=xyz",
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("accept")).toBe("application/json");
      expect(result.get("x-custom-header")).toBeNull();
      expect(result.get("authorization")).toBeNull();
      expect(result.get("cookie")).toBeNull();
    });

    it("should handle case-insensitive header names", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          Accept: "application/json",
          "Content-Type": "text/plain",
          "User-Agent": "Mozilla/5.0",
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("accept")).toBe("application/json");
      expect(result.get("content-type")).toBe("text/plain");
      expect(result.get("user-agent")).toBe("Mozilla/5.0");
    });

    it("should handle empty headers", () => {
      const request = new NextRequest("https://example.com");

      const result = buildForwardedRequestHeaders(request);

      expect(Array.from(result.keys()).length).toBe(0);
    });

    it("should forward caching and conditional request headers", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          "cache-control": "no-cache",
          "if-none-match": '"abc123"',
          "if-modified-since": "Wed, 21 Oct 2015 07:28:00 GMT",
          etag: '"xyz789"',
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("cache-control")).toBe("no-cache");
      expect(result.get("if-none-match")).toBe('"abc123"');
      expect(result.get("if-modified-since")).toBe(
        "Wed, 21 Oct 2015 07:28:00 GMT"
      );
      expect(result.get("etag")).toBe('"xyz789"');
    });

    it("should forward tracing and observability headers", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          traceparent: "00-abc123-def456-01",
          tracestate: "vendor=value",
          "x-correlation-id": "corr-123",
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("traceparent")).toBe("00-abc123-def456-01");
      expect(result.get("tracestate")).toBe("vendor=value");
      expect(result.get("x-correlation-id")).toBe("corr-123");
    });

    it("should forward proxy headers for IP and rate limiting", () => {
      const request = new NextRequest("https://example.com", {
        headers: {
          "x-forwarded-for": "192.168.1.1, 10.0.0.1",
          "x-forwarded-host": "example.com",
          "x-forwarded-proto": "https",
          "x-real-ip": "192.168.1.1",
        },
      });

      const result = buildForwardedRequestHeaders(request);

      expect(result.get("x-forwarded-for")).toBe("192.168.1.1, 10.0.0.1");
      expect(result.get("x-forwarded-host")).toBe("example.com");
      expect(result.get("x-forwarded-proto")).toBe("https");
      expect(result.get("x-real-ip")).toBe("192.168.1.1");
    });
  });

  describe("buildForwardedResponseHeaders", () => {
    it("should forward all headers except hop-by-hop headers", () => {
      const response = new Response("body", {
        headers: {
          "content-type": "application/json",
          "cache-control": "max-age=3600",
          "x-custom-header": "custom-value",
          etag: '"abc123"',
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("content-type")).toBe("application/json");
      expect(result.get("cache-control")).toBe("max-age=3600");
      expect(result.get("x-custom-header")).toBe("custom-value");
      expect(result.get("etag")).toBe('"abc123"');
    });

    it("should strip all hop-by-hop headers", () => {
      const response = new Response("body", {
        headers: {
          "content-type": "application/json",
          connection: "keep-alive",
          "keep-alive": "timeout=5",
          "proxy-authenticate": "Basic",
          "proxy-authorization": "Bearer token",
          te: "trailers",
          trailer: "Expires",
          "transfer-encoding": "chunked",
          upgrade: "h2c",
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("content-type")).toBe("application/json");
      expect(result.get("connection")).toBeNull();
      expect(result.get("keep-alive")).toBeNull();
      expect(result.get("proxy-authenticate")).toBeNull();
      expect(result.get("proxy-authorization")).toBeNull();
      expect(result.get("te")).toBeNull();
      expect(result.get("trailer")).toBeNull();
      expect(result.get("transfer-encoding")).toBeNull();
      expect(result.get("upgrade")).toBeNull();
    });

    it("should handle case-insensitive hop-by-hop headers", () => {
      const response = new Response("body", {
        headers: {
          "content-type": "application/json",
          Connection: "Keep-Alive",
          "Transfer-Encoding": "chunked",
          Upgrade: "WebSocket",
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("content-type")).toBe("application/json");
      expect(result.get("connection")).toBeNull();
      expect(result.get("transfer-encoding")).toBeNull();
      expect(result.get("upgrade")).toBeNull();
    });

    it("should handle empty headers", () => {
      const response = new Response("body");

      const result = buildForwardedResponseHeaders(response);

      // Response objects may have default headers like content-type
      // So we just check that hop-by-hop headers are not present
      expect(result.get("connection")).toBeNull();
      expect(result.get("upgrade")).toBeNull();
    });

    it("should forward standard response headers", () => {
      const response = new Response("body", {
        headers: {
          "content-type": "application/json",
          "content-length": "123",
          "content-encoding": "gzip",
          "content-language": "en-US",
          date: "Wed, 21 Oct 2015 07:28:00 GMT",
          expires: "Thu, 22 Oct 2015 07:28:00 GMT",
          "last-modified": "Tue, 20 Oct 2015 07:28:00 GMT",
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("content-type")).toBe("application/json");
      expect(result.get("content-length")).toBe("123");
      expect(result.get("content-encoding")).toBe("gzip");
      expect(result.get("content-language")).toBe("en-US");
      expect(result.get("date")).toBe("Wed, 21 Oct 2015 07:28:00 GMT");
      expect(result.get("expires")).toBe("Thu, 22 Oct 2015 07:28:00 GMT");
      expect(result.get("last-modified")).toBe("Tue, 20 Oct 2015 07:28:00 GMT");
    });

    it("should forward security headers", () => {
      const response = new Response("body", {
        headers: {
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "x-xss-protection": "1; mode=block",
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("strict-transport-security")).toBe("max-age=31536000");
      expect(result.get("content-security-policy")).toBe("default-src 'self'");
      expect(result.get("x-frame-options")).toBe("DENY");
      expect(result.get("x-content-type-options")).toBe("nosniff");
      expect(result.get("x-xss-protection")).toBe("1; mode=block");
    });

    it("should forward CORS headers", () => {
      const response = new Response("body", {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, PUT",
          "access-control-allow-headers": "Content-Type, Authorization",
          "access-control-max-age": "86400",
          "access-control-expose-headers": "X-Custom-Header",
        },
      });

      const result = buildForwardedResponseHeaders(response);

      expect(result.get("access-control-allow-origin")).toBe("*");
      expect(result.get("access-control-allow-methods")).toBe("GET, POST, PUT");
      expect(result.get("access-control-allow-headers")).toBe(
        "Content-Type, Authorization"
      );
      expect(result.get("access-control-max-age")).toBe("86400");
      expect(result.get("access-control-expose-headers")).toBe(
        "X-Custom-Header"
      );
    });
  });
});
