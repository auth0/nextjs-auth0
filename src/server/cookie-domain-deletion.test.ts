import { describe, it, expect } from "vitest";
import { deleteCookie, deleteChunkedCookie } from "./cookies.js";
import { ResponseCookies, RequestCookies } from "@edge-runtime/cookies";

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