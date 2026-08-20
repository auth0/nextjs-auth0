import { NextRequest } from "next/server.js";
import { describe, expect, it } from "vitest";

import { isNonNavigationalRequest, isRequest } from "./request.js";

describe("isNonNavigationalRequest", () => {
  const makeReq = (headers: Record<string, string>) => {
    const req = new NextRequest("http://localhost:3000/auth/login");
    Object.entries(headers).forEach(([k, v]) => req.headers.set(k, v));
    return req;
  };

  describe("known prefetch headers — positive detection only", () => {
    it("returns true when next-router-prefetch is 1 (Next 15 AUTO prefetch)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "next-router-prefetch": "1" }))
      ).toBe(true);
    });

    it("returns true when next-router-prefetch is 2 (Next 16 runtime prefetch)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "next-router-prefetch": "2" }))
      ).toBe(true);
    });

    it("returns true when purpose is prefetch", () => {
      expect(isNonNavigationalRequest(makeReq({ purpose: "prefetch" }))).toBe(
        true
      );
    });

    it("returns true when sec-purpose is prefetch", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-purpose": "prefetch" }))
      ).toBe(true);
    });

    it("returns true when x-middleware-prefetch is 1 (Pages Router)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "x-middleware-prefetch": "1" }))
      ).toBe(true);
    });
  });

  describe("requests that must not be blocked", () => {
    it("returns false for plain navigation with no prefetch headers", () => {
      expect(isNonNavigationalRequest(makeReq({ accept: "text/html" }))).toBe(
        false
      );
    });

    it("returns false for accept: text/x-component — real RSC <Link> navigation must not be blocked", () => {
      // text/x-component is sent by ALL App Router RSC requests, including a
      // genuine client-side <Link prefetch={false}> click — not just prefetches.
      expect(
        isNonNavigationalRequest(makeReq({ accept: "text/x-component" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: navigate", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "navigate" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: cors — legitimate fetch()/XHR must not be blocked", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "cors" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: same-origin — legitimate fetch()/XHR must not be blocked", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "same-origin" }))
      ).toBe(false);
    });

    it("returns false for sec-purpose: prefetch;prerender — Speculation Rules prerender must not be blocked", () => {
      // A prerender is the real navigation executed ahead of time. Blocking it
      // with 204 would silently swallow the login click when the user navigates.
      expect(
        isNonNavigationalRequest(
          makeReq({ "sec-purpose": "prefetch;prerender" })
        )
      ).toBe(false);
    });

    it("returns false when no headers present", () => {
      expect(isNonNavigationalRequest(makeReq({}))).toBe(false);
    });
  });
});

describe("isRequest", () => {
  it("returns true for a Fetch Request instance", () => {
    const req = new Request("https://example.com/api");
    expect(isRequest(req)).toBe(true);
  });

  it("returns true for an object with Headers instance", () => {
    const req = { headers: new Headers({ "x-test": "1" }) };
    expect(isRequest(req as any)).toBe(true);
  });

  it("returns true for an object exposing bodyUsed", () => {
    const req = { bodyUsed: false };
    expect(isRequest(req as any)).toBe(true);
  });

  it("returns false for plain objects without request traits", () => {
    const req = { headers: { "x-test": "1" } };
    expect(isRequest(req as any)).toBe(false);
  });
});
