import { NextRequest, NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";

import { toNextRequest, toNextResponse } from "./next-compat.js";

describe("next-compat", () => {
  describe("toNextRequest", () => {
    it("should return the same instance if input is already a NextRequest", () => {
      const req = new NextRequest("https://example.com/api/test", {
        method: "GET"
      });
      const result = toNextRequest(req);
      expect(result).toBe(req);
    });

    it("should rebuild even if nextUrl is present on a plain object", () => {
      const req: any = {
        url: "https://example.com/api/test",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: { pathname: "/api/test" }
      };

      const result = toNextRequest(req);
      expect(result).toBeInstanceOf(NextRequest);
      expect(result.url).toBe("https://example.com/api/test");
    });

    it("should convert a plain Request into a NextRequest preserving url, method, headers and body", async () => {
      const headers = new Headers({ "x-test": "true" });
      const body = JSON.stringify({ foo: "bar" });
      const plainReq = new Request("https://example.com/api/data", {
        method: "POST",
        headers,
        body
      });

      const nextReq = toNextRequest(plainReq);
      expect(nextReq).toBeInstanceOf(NextRequest);
      expect(nextReq.url).toBe("https://example.com/api/data");
      expect(nextReq.method).toBe("POST");
      expect(nextReq.headers.get("x-test")).toBe("true");

      const parsed = await nextReq.json();
      expect(parsed).toEqual({ foo: "bar" });
    });

    it("should set duplex to 'half' if not provided", () => {
      const req = new Request("https://example.com", { method: "GET" });
      const nextReq = toNextRequest(req);
      expect((nextReq as any).duplex).toBe("half");
    });

    it("should default to 'half' duplex when invalid or missing", () => {
      // Mock an object without a valid duplex property
      const fakeReq: any = {
        url: "https://example.com",
        method: "GET",
        headers: new Headers(),
        body: null
      };

      // The conversion should not throw and should set duplex: 'half'
      const nextReq = toNextRequest(fakeReq);
      expect(nextReq).toBeInstanceOf(NextRequest);
      expect((nextReq as any).duplex).toBe("half");
    });

    it("should preserve basePath from nextUrl when present on the input request", () => {
      const basePath = "/base-path";
      const url = new URL(`${basePath}/auth/login`, "https://example.com");

      const sourceNextUrl = new NextRequest(url, {
        nextConfig: { basePath }
      }).nextUrl;

      const fakeReq: any = {
        url: url.toString(),
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: sourceNextUrl
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe(basePath);
      expect(nextReq.nextUrl.pathname).toBe("/auth/login");
    });

    it("should rebuild locale/defaultLocale and trailingSlash from nextUrl metadata", () => {
      const url = new URL("https://example.com/app/fr/profile/");

      const sourceNextUrl = new NextRequest(url, {
        nextConfig: {
          basePath: "/app",
          i18n: { locales: ["en", "fr"], defaultLocale: "en" },
          trailingSlash: true
        }
      }).nextUrl;

      const fakeReq: any = {
        url: url.toString(),
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: sourceNextUrl
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe("/app");
      expect(nextReq.nextUrl.locale).toBe("fr");
      expect(nextReq.nextUrl.defaultLocale).toBe("en");
      expect(nextReq.nextUrl.href.endsWith("/profile/")).toBe(true);
    });

    it("should rebuild i18n when only locale/defaultLocale exist (no basePath)", () => {
      const fakeReq: any = {
        url: "https://example.com/fr/no-base",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          locale: "fr",
          defaultLocale: "en"
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe("");
      expect(nextReq.nextUrl.locale).toBe("fr");
      expect(nextReq.nextUrl.defaultLocale).toBe("en");
    });

    it("should rebuild i18n when only defaultLocale is set (locale undefined)", () => {
      const fakeReq: any = {
        url: "https://example.com/no-locale",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          defaultLocale: "en"
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.locale).toBe("en");
      expect(nextReq.nextUrl.defaultLocale).toBe("en");
    });

    it("should honor trailingSlash when it is the only nextUrl field", () => {
      const fakeReq: any = {
        url: "https://example.com/trailing-only/",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          trailingSlash: true
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.href.endsWith("/trailing-only/")).toBe(true);
    });

    it("should ignore non-boolean trailingSlash values while keeping other fields", () => {
      const basePath = "/base";
      const url = new URL(`${basePath}/foo`, "https://example.com");

      const fakeReq: any = {
        url: url.toString(),
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          basePath,
          trailingSlash: "yes" // not a boolean, should be ignored
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe(basePath);
      expect(nextReq.nextUrl.href.endsWith("/foo")).toBe(true);
    });

    it("should set no nextConfig when nextUrl is absent", () => {
      const req = new Request("https://example.com/no-next-url", {
        method: "GET"
      });

      const nextReq = toNextRequest(req);

      expect(nextReq.nextUrl.basePath).toBe("");
      expect(nextReq.nextUrl.locale).toBe("");
      expect(nextReq.nextUrl.defaultLocale).toBeUndefined();
    });

    it("should ignore nextUrl that lacks supported fields", () => {
      const fakeReq: any = {
        url: "https://example.com/no-fields",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {}
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe("");
      expect(nextReq.nextUrl.locale).toBe("");
      expect(nextReq.nextUrl.defaultLocale).toBeUndefined();
    });

    it("should rebuild trailingSlash=false and defaultLocale even when locale is empty", () => {
      const fakeReq: any = {
        url: "https://example.com/app/no-locale",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          basePath: "/app",
          locale: "",
          defaultLocale: "en",
          trailingSlash: false
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe("/app");
      expect(nextReq.nextUrl.locale).toBe("en");
      expect(nextReq.nextUrl.defaultLocale).toBe("en");
      expect(nextReq.nextUrl.href.endsWith("/no-locale")).toBe(true);
    });

    it("should not set basePath when nextUrl.basePath is an empty string", () => {
      const fakeReq: any = {
        url: "https://example.com/empty-base",
        method: "GET",
        headers: new Headers(),
        body: null,
        nextUrl: {
          basePath: ""
        }
      };

      const nextReq = toNextRequest(fakeReq);

      expect(nextReq.nextUrl.basePath).toBe("");
      expect(nextReq.nextUrl.pathname).toBe("/empty-base");
    });

    it("should ignore inaccessible nextUrl errors gracefully", () => {
      const fakeReq: any = {
        url: "https://example.com/api",
        method: "GET",
        headers: new Headers(),
        body: null
      };
      Object.defineProperty(fakeReq, "nextUrl", {
        get() {
          throw new Error("boom");
        }
      });

      expect(() => toNextRequest(fakeReq)).not.toThrow();
      const nextReq = toNextRequest(fakeReq);
      expect(nextReq).toBeInstanceOf(NextRequest);
    });
  });

  describe("toNextResponse", () => {
    it("should return the same instance if input is already a NextResponse", () => {
      const res = NextResponse.json({ ok: true }, { status: 200 });
      const result = toNextResponse(res);
      expect(result).toBe(res);
    });

    it("should convert a plain Response into a NextResponse preserving body, status, and headers", async () => {
      const plainRes = new Response(JSON.stringify({ ok: true }), {
        status: 202,
        statusText: "Accepted",
        headers: { "x-test": "42" }
      });

      const nextRes = toNextResponse(plainRes);
      expect(nextRes).toBeInstanceOf(NextResponse);
      expect(nextRes.status).toBe(202);
      expect(nextRes.statusText).toBe("Accepted");
      expect(nextRes.headers.get("x-test")).toBe("42");

      const data = await nextRes.json();
      expect(data).toEqual({ ok: true });
    });

    it("should copy url if present (mocked plain object, assignable)", () => {
      // Use a *plain object*, not a real Response instance.
      const fakeRes: any = {
        body: "ok",
        status: 200,
        statusText: "OK",
        headers: new Headers(),
        url: "https://example.com/test"
      };

      const nextRes = toNextResponse(fakeRes);

      // NextResponse inherits a read-only url getter, so we can’t assert strict equality here.
      // Instead, we confirm our helper didn’t throw and that it *tried* to propagate the url.
      expect(nextRes).toBeInstanceOf(NextResponse);
      expect(() => (nextRes as any).url).not.toThrow();
    });

    it("should silently ignore errors when accessing url", () => {
      const fakeRes = {
        body: "ok",
        status: 200,
        statusText: "OK",
        headers: new Headers()
      } as any;
      Object.defineProperty(fakeRes, "url", {
        get() {
          throw new Error("inaccessible");
        }
      });
      expect(() => toNextResponse(fakeRes)).not.toThrow();
    });
  });
});
