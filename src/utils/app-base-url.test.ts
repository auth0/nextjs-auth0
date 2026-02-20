import { NextRequest } from "next/server.js";
import { describe, expect, it } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import {
  inferBaseUrlFromRequest,
  normalizeAppBaseUrl,
  resolveAppBaseUrl
} from "./app-base-url.js";

describe("normalizeAppBaseUrl", () => {
  it("should return undefined when neither appBaseUrl nor APP_BASE_URL is provided", () => {
    expect(normalizeAppBaseUrl(undefined, undefined)).toBeUndefined();
  });

  it("should prefer appBaseUrl input over APP_BASE_URL env", () => {
    expect(
      normalizeAppBaseUrl(
        "https://input.example.com",
        "https://env.example.com"
      )
    ).toEqual("https://input.example.com");
  });

  it("should preserve query/hash and trailing slash in a single appBaseUrl input", () => {
    expect(normalizeAppBaseUrl("https://example.com/base/?a=1#hash")).toEqual(
      "https://example.com/base/?a=1#hash"
    );
  });

  it("should throw InvalidConfigurationError for blank appBaseUrl input", () => {
    expect(() => normalizeAppBaseUrl("   ")).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrl("   ")).toThrowError(
      "appBaseUrl must be a non-empty URL."
    );
  });

  it("should throw InvalidConfigurationError for non-string appBaseUrl input types", () => {
    expect(() => normalizeAppBaseUrl(123 as unknown as string)).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrl(123 as unknown as string)).toThrowError(
      "appBaseUrl must be a URL string."
    );
  });

  it("should throw InvalidConfigurationError for non-absolute appBaseUrl input", () => {
    expect(() => normalizeAppBaseUrl("not-a-url")).toThrowError(
      InvalidConfigurationError
    );
    expect(() => normalizeAppBaseUrl("not-a-url")).toThrowError(
      "appBaseUrl must be an absolute URL."
    );
  });

  it("should accept non-http(s) appBaseUrl input values as-is", () => {
    expect(normalizeAppBaseUrl("ftp://example.com")).toEqual(
      "ftp://example.com"
    );
  });

  it("should treat a single APP_BASE_URL value as a static base URL", () => {
    expect(normalizeAppBaseUrl(undefined, "https://env.example.com/")).toEqual(
      "https://env.example.com/"
    );
  });

  it("should return undefined when APP_BASE_URL env is blank", () => {
    expect(normalizeAppBaseUrl(undefined, "")).toBeUndefined();
  });

  it("should return undefined when APP_BASE_URL env is only whitespace", () => {
    expect(normalizeAppBaseUrl(undefined, "   ")).toBeUndefined();
  });

  it("should accept non-http APP_BASE_URL values as-is", () => {
    expect(normalizeAppBaseUrl(undefined, "mailto:ops@example.com")).toEqual(
      "mailto:ops@example.com"
    );
  });

  it("should throw when APP_BASE_URL contains multiple values", () => {
    expect(() =>
      normalizeAppBaseUrl(
        undefined,
        "https://a.example.com, https://b.example.com"
      )
    ).toThrowError(InvalidConfigurationError);
    expect(() =>
      normalizeAppBaseUrl(
        undefined,
        "https://a.example.com, https://b.example.com"
      )
    ).toThrowError("APP_BASE_URL must be an absolute URL.");
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

  it("should return null when inferred protocol is not http(s)", () => {
    const req = new NextRequest(new URL("http://internal.local/path"), {
      headers: {
        "x-forwarded-host": "preview.example.com",
        "x-forwarded-proto": "ftp"
      }
    });

    expect(inferBaseUrlFromRequest(req)).toBeNull();
  });
});

describe("resolveAppBaseUrl", () => {
  it("should return the static appBaseUrl when configured", () => {
    const req = new NextRequest(new URL("https://ignored.example.com"));
    expect(resolveAppBaseUrl("https://static.example.com", req)).toBe(
      "https://static.example.com"
    );
  });

  it("should infer the base URL from the request when no appBaseUrl is configured", () => {
    const req = new NextRequest(new URL("https://app.example.com/path"));
    expect(resolveAppBaseUrl(undefined, req)).toBe("https://app.example.com");
  });

  it("should throw when the request does not provide host/proto information", () => {
    const req = {
      headers: new Headers()
    } as unknown as NextRequest;

    expect(() => resolveAppBaseUrl(undefined, req)).toThrowError(
      InvalidConfigurationError
    );
  });

  it("should throw when no appBaseUrl is configured and no request is provided", () => {
    expect(() => resolveAppBaseUrl(undefined)).toThrowError(
      InvalidConfigurationError
    );
  });
});
