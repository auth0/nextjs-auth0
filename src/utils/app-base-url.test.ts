import { NextRequest } from "next/server.js";
import { describe, expect, it } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import {
  inferBaseUrlFromRequest,
  normalizeAppBaseUrlConfig
} from "./app-base-url.js";

describe("normalizeAppBaseUrlConfig", () => {
  it("should return undefined when neither appBaseUrl nor APP_BASE_URL is provided", () => {
    expect(normalizeAppBaseUrlConfig(undefined, undefined)).toBeUndefined();
  });

  it("should prefer appBaseUrl input over APP_BASE_URL env", () => {
    expect(
      normalizeAppBaseUrlConfig(
        "https://input.example.com",
        "https://env.example.com"
      )
    ).toEqual(["https://input.example.com"]);
  });

  it("should strip query/hash and trailing slash from a single appBaseUrl input", () => {
    expect(
      normalizeAppBaseUrlConfig("https://example.com/base/?a=1#hash")
    ).toEqual(["https://example.com/base"]);
  });

  it("should split comma-separated appBaseUrl input and normalize each entry", () => {
    expect(
      normalizeAppBaseUrlConfig(
        " https://a.example.com/ , http://b.example.com/base/?x=1#y "
      )
    ).toEqual(["https://a.example.com", "http://b.example.com/base"]);
  });

  it("should ignore non-string or blank entries in appBaseUrl array input", () => {
    const input = [
      "https://a.example.com",
      123 as unknown as string,
      "  ",
      "http://b.example.com/"
    ];
    expect(normalizeAppBaseUrlConfig(input)).toEqual([
      "https://a.example.com",
      "http://b.example.com"
    ]);
  });

  it("should return undefined when appBaseUrl array contains no usable entries", () => {
    const input = ["   ", ""];
    expect(normalizeAppBaseUrlConfig(input)).toBeUndefined();
  });

  it("should throw InvalidConfigurationError for blank appBaseUrl input", () => {
    expect(() => normalizeAppBaseUrlConfig("   ")).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrlConfig("   ")).toThrowError(
      "appBaseUrl must be a non-empty URL."
    );
  });

  it("should ignore non-string appBaseUrl input types", () => {
    expect(normalizeAppBaseUrlConfig(123 as unknown as string)).toBeUndefined();
  });

  it("should throw InvalidConfigurationError for non-absolute appBaseUrl input", () => {
    expect(() => normalizeAppBaseUrlConfig("not-a-url")).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrlConfig("not-a-url")).toThrowError(
      "appBaseUrl must be an absolute URL."
    );
  });

  it("should throw InvalidConfigurationError for non-http(s) appBaseUrl input", () => {
    expect(() => normalizeAppBaseUrlConfig("ftp://example.com")).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrlConfig("ftp://example.com")).toThrowError(
      "appBaseUrl must use http or https."
    );
  });

  it("should parse and normalize comma-separated APP_BASE_URL allow lists", () => {
    expect(
      normalizeAppBaseUrlConfig(
        undefined,
        "https://a.example.com, http://b.example.com/"
      )
    ).toEqual(["https://a.example.com", "http://b.example.com"]);
  });

  it("should return undefined when APP_BASE_URL env is blank", () => {
    expect(normalizeAppBaseUrlConfig(undefined, " , ")).toBeUndefined();
  });

  it("should include APP_BASE_URL in error messages for invalid env values", () => {
    expect(() =>
      normalizeAppBaseUrlConfig(undefined, "mailto:ops@example.com")
    ).toThrowError(InvalidConfigurationError);
    expect(() =>
      normalizeAppBaseUrlConfig(undefined, "mailto:ops@example.com")
    ).toThrowError("APP_BASE_URL must use http or https.");
  });
});

describe("inferBaseUrlFromRequest", () => {
  it("should prefer x-forwarded headers and first values when multiple provided", () => {
    const req = new NextRequest(new URL("http://internal.local/path"), {
      headers: {
        "x-forwarded-host": " preview.example.com , proxy.local ",
        "x-forwarded-proto": " https , http "
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBe("https://preview.example.com");
  });

  it("should treat empty forwarded header values as missing", () => {
    const req = new NextRequest(new URL("https://app.example.com/path"), {
      headers: {
        "x-forwarded-host": " , ",
        "x-forwarded-proto": " , "
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBe("https://app.example.com");
  });

  it("should fall back to host header when x-forwarded-host is missing", () => {
    const req = new NextRequest(new URL("http://internal.local/path"), {
      headers: {
        host: "app.example.com",
        "x-forwarded-proto": "https"
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBe("https://app.example.com");
  });

  it("should fall back to nextUrl when host/proto headers are missing", () => {
    const req = new NextRequest(new URL("https://app.example.com/some/path"));

    expect(inferBaseUrlFromRequest(req)).toBe("https://app.example.com");
  });

  it("should combine x-forwarded-host with nextUrl protocol when proto is missing", () => {
    const req = new NextRequest(new URL("https://internal.local/path"), {
      headers: {
        "x-forwarded-host": "preview.example.com"
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBe("https://preview.example.com");
  });

  it("should combine x-forwarded-proto with nextUrl host when host header is missing", () => {
    const req = new NextRequest(new URL("http://preview.example.com/path"), {
      headers: {
        "x-forwarded-proto": "https"
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBe("https://preview.example.com");
  });

  it("should return null when host cannot be resolved", () => {
    const req = {
      headers: new Headers({ "x-forwarded-proto": "https" })
    } as unknown as NextRequest;

    expect(inferBaseUrlFromRequest(req)).toBeNull();
  });

  it("should return null when protocol cannot be resolved", () => {
    const req = {
      headers: new Headers({ host: "app.example.com" })
    } as unknown as NextRequest;

    expect(inferBaseUrlFromRequest(req)).toBeNull();
  });

  it("should return null when inferred host/proto yields an invalid URL", () => {
    const req = new NextRequest(new URL("http://internal.local/path"), {
      headers: {
        "x-forwarded-host": "bad host",
        "x-forwarded-proto": "https"
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBeNull();
  });
});
