import { describe, expect, it } from "vitest";

import payloads from "../test/fixtures/open-redirect-payloads.json";
import { toSafeRedirect } from "./url-helpers";

describe("url-helpers", () => {
  const safeBaseUrl = new URL("http://www.example.com");

  describe("isSafeRedirect", () => {
    it("should not allow absolute urls", () => {
      expect(toSafeRedirect("file://foo", safeBaseUrl)).toEqual(undefined);
      expect(toSafeRedirect("https://foo", safeBaseUrl)).toEqual(undefined);
      expect(toSafeRedirect("http://foo", safeBaseUrl)).toEqual(undefined);
    });

    it("should allow relative urls", () => {
      expect(toSafeRedirect("/foo", safeBaseUrl)).toEqual(
        "http://www.example.com/foo"
      );
      expect(toSafeRedirect("foo", safeBaseUrl)).toEqual(
        "http://www.example.com/foo"
      );
      expect(toSafeRedirect("/foo?some=value", safeBaseUrl)).toEqual(
        "http://www.example.com/foo?some=value"
      );
      expect(
        toSafeRedirect("/foo?someUrl=https://www.google.com", safeBaseUrl)
      ).toEqual("http://www.example.com/foo?someUrl=https://www.google.com");
      expect(
        toSafeRedirect("/foo", new URL("http://www.example.com:8888"))
      ).toEqual("http://www.example.com:8888/foo");
    });

    it("should prevent open redirects", () => {
      for (const payload of payloads) {
        expect(
          toSafeRedirect(payload, safeBaseUrl) || safeBaseUrl.toString()
        ).toMatch(/^http:\/\/www.example.com\//);
      }
    });

    it("should not throw for empty redirect", () => {
      expect(toSafeRedirect.bind(null, "", safeBaseUrl)).not.toThrow();
    });
  });
});
