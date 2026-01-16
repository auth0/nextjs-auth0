import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { describe, expect, it } from "vitest";

import { deleteChunkedCookie, deleteCookie } from "./cookies.js";

describe("Cookie deletion with domain", () => {
  it("should delete cookies without domain by default", () => {
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);

    deleteCookie(resCookies, "__session");

    const setCookieHeaders = headers.getSetCookie();
    const sessionCookieHeader = setCookieHeaders.find((header) =>
      header.includes("__session=")
    );

    expect(sessionCookieHeader).toContain("Max-Age=0");
    expect(sessionCookieHeader).not.toContain("Domain=");
  });

  it("should include domain when deleting cookies if domain option is provided", () => {
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);
    const cookieDomain = "df.mydomain.com";

    deleteCookie(resCookies, "__session", {
      domain: cookieDomain,
      path: "/"
    });

    const setCookieHeaders = headers.getSetCookie();
    const sessionCookieHeader = setCookieHeaders.find((header) =>
      header.includes("__session=")
    );

    expect(sessionCookieHeader).toContain(`Domain=${cookieDomain}`);
    expect(sessionCookieHeader).toContain("Max-Age=0");
  });

  it("should delete chunked cookies with domain when provided", () => {
    const headers = new Headers();
    const reqCookies = new RequestCookies(headers);
    const resCookies = new ResponseCookies(headers);

    reqCookies.set("__session__0", "chunk0");
    reqCookies.set("__session__1", "chunk1");

    const cookieDomain = "df.mydomain.com";

    deleteChunkedCookie("__session", reqCookies, resCookies, false, {
      domain: cookieDomain,
      path: "/"
    });

    const setCookieHeaders = headers.getSetCookie();

    setCookieHeaders.forEach((header) => {
      expect(header).toContain(`Domain=${cookieDomain}`);
      expect(header).toContain("Max-Age=0");
    });

    expect(setCookieHeaders.length).toBeGreaterThanOrEqual(3);
  });
});

describe("Dual-domain cookie deletion (rawHeaders)", () => {
  it("should emit both domain and host-only deletion headers when rawHeaders is provided with domain", () => {
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);
    const cookieDomain = ".example.com";

    // Pass rawHeaders to enable dual-domain deletion
    deleteCookie(
      resCookies,
      "__session",
      {
        domain: cookieDomain,
        path: "/"
      },
      headers
    );

    const setCookieHeaders = headers.getSetCookie();

    // Should have 2 headers: one with domain, one without (host-only)
    expect(setCookieHeaders.length).toBe(2);

    // Find domain variant
    const domainHeader = setCookieHeaders.find(
      (header) =>
        header.includes("__session=") &&
        header.includes(`Domain=${cookieDomain}`)
    );
    expect(domainHeader).toBeDefined();
    expect(domainHeader).toContain("Max-Age=0");

    // Find host-only variant (no Domain attribute)
    const hostOnlyHeader = setCookieHeaders.find(
      (header) => header.includes("__session=") && !header.includes("Domain=")
    );
    expect(hostOnlyHeader).toBeDefined();
    expect(hostOnlyHeader).toContain("Max-Age=0");
  });

  it("should emit single header when rawHeaders is not provided (backward compat)", () => {
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);
    const cookieDomain = ".example.com";

    // No rawHeaders - existing behavior
    deleteCookie(resCookies, "__session", {
      domain: cookieDomain,
      path: "/"
    });

    const setCookieHeaders = headers.getSetCookie();

    // Should have only 1 header (domain variant from ResponseCookies.set)
    expect(setCookieHeaders.length).toBe(1);
    expect(setCookieHeaders[0]).toContain(`Domain=${cookieDomain}`);
  });

  it("should emit single header when rawHeaders is provided but no domain", () => {
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);

    // rawHeaders provided but no domain - no extra header needed
    deleteCookie(
      resCookies,
      "__session",
      {
        path: "/"
      },
      headers
    );

    const setCookieHeaders = headers.getSetCookie();

    // Should have only 1 header (host-only)
    expect(setCookieHeaders.length).toBe(1);
    expect(setCookieHeaders[0]).not.toContain("Domain=");
  });

  it("should emit dual headers per chunk when deleting chunked cookies with rawHeaders", () => {
    const reqHeaders = new Headers();
    const reqCookies = new RequestCookies(reqHeaders);

    // Setup existing chunks in request
    reqCookies.set("__session__0", "chunk0");
    reqCookies.set("__session__1", "chunk1");

    const resHeaders = new Headers();
    const resCookies = new ResponseCookies(resHeaders);
    const cookieDomain = ".example.com";

    // Delete chunked cookie with rawHeaders
    deleteChunkedCookie(
      "__session",
      reqCookies,
      resCookies,
      false,
      {
        domain: cookieDomain,
        path: "/"
      },
      resHeaders
    );

    const setCookieHeaders = resHeaders.getSetCookie();

    // Should have 6 headers: 3 cookies (main + 2 chunks) × 2 (domain + host-only)
    expect(setCookieHeaders.length).toBe(6);

    // Verify main cookie has both variants
    const mainDomainHeader = setCookieHeaders.find(
      (header) =>
        header.startsWith("__session=") &&
        header.includes(`Domain=${cookieDomain}`)
    );
    expect(mainDomainHeader).toBeDefined();

    const mainHostOnlyHeader = setCookieHeaders.find(
      (header) => header.startsWith("__session=") && !header.includes("Domain=")
    );
    expect(mainHostOnlyHeader).toBeDefined();

    // Verify chunks have both variants
    const chunk0DomainHeader = setCookieHeaders.find(
      (header) =>
        header.includes("__session__0=") &&
        header.includes(`Domain=${cookieDomain}`)
    );
    expect(chunk0DomainHeader).toBeDefined();

    const chunk0HostOnlyHeader = setCookieHeaders.find(
      (header) =>
        header.includes("__session__0=") && !header.includes("Domain=")
    );
    expect(chunk0HostOnlyHeader).toBeDefined();
  });
});
