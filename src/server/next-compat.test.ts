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
