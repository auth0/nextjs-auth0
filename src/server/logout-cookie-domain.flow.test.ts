import { ResponseCookies } from "@edge-runtime/cookies";
import { describe, expect, it } from "vitest";

import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { Auth0RequestCookies, Auth0ResponseCookies } from "./http/index.js";

describe("Session cookie domain deletion bug", () => {
  it("should delete session cookies with domain when AUTH0_COOKIE_DOMAIN is set", () => {
    // Create session store with domain configured
    const sessionStore = new StatelessSessionStore({
      secret: "a-very-long-secret-that-is-at-least-32-characters-long",
      cookieOptions: {
        domain: "df.mydomain.com", // This simulates AUTH0_COOKIE_DOMAIN
        path: "/",
        secure: true,
        sameSite: "lax"
      }
    });

    // Mock request and response cookies
    const headers = new Headers();
    const reqCookies = new Headers();
    const resCookies = new Auth0ResponseCookies(new ResponseCookies(headers));

    // Add session cookie to request (simulate existing session)
    reqCookies.set("__session", "existing-session-value");

    // Mock request cookies to properly simulate RequestCookies interface
    const mockReqCookies = {
      get: (name: string) => ({ value: reqCookies.get(name) }),
      getAll: () =>
        Array.from(reqCookies.entries()).map(([name, value]) => ({
          name,
          value
        })),
      set: (name: string, value: string) => reqCookies.set(name, value),
      delete: (name: string) => reqCookies.delete(name),
      has: (name: string) => reqCookies.has(name)
    };

    // Call delete method
    sessionStore.delete(new Auth0RequestCookies(mockReqCookies as any), resCookies);

    // Check that cookies are deleted with domain
    const setCookieHeaders = headers.getSetCookie();

    // Should have at least one cookie deletion header
    expect(setCookieHeaders.length).toBeGreaterThan(0);

    // Find the session cookie deletion header
    const sessionDeletionHeader = setCookieHeaders.find(
      (header) => header.includes("__session=") && header.includes("Max-Age=0")
    );

    expect(sessionDeletionHeader).toBeDefined();

    // This is the key assertion - cookie deletion should include domain
    expect(sessionDeletionHeader).toContain("Domain=df.mydomain.com");
    expect(sessionDeletionHeader).toContain("Max-Age=0");
    expect(sessionDeletionHeader).toContain("Path=/");
  });

  it("should work without domain when AUTH0_COOKIE_DOMAIN is not set", () => {
    // Create session store without domain (default behavior)
    const sessionStore = new StatelessSessionStore({
      secret: "a-very-long-secret-that-is-at-least-32-characters-long",
      cookieOptions: {
        path: "/",
        secure: true,
        sameSite: "lax"
        // no domain specified
      }
    });

    const headers = new Headers();
    const reqCookies = new Headers();
    const resCookies = new Auth0ResponseCookies(new ResponseCookies(headers));

    reqCookies.set("__session", "existing-session-value");

    const mockReqCookies = {
      get: (name: string) => ({ value: reqCookies.get(name) }),
      getAll: () =>
        Array.from(reqCookies.entries()).map(([name, value]) => ({
          name,
          value
        })),
      set: (name: string, value: string) => reqCookies.set(name, value),
      delete: (name: string) => reqCookies.delete(name),
      has: (name: string) => reqCookies.has(name)
    };

    sessionStore.delete(mockReqCookies as any, resCookies);

    const setCookieHeaders = headers.getSetCookie();
    const sessionDeletionHeader = setCookieHeaders.find(
      (header) => header.includes("__session=") && header.includes("Max-Age=0")
    );

    expect(sessionDeletionHeader).toBeDefined();

    // Should not include domain when none is configured
    expect(sessionDeletionHeader).not.toContain("Domain=");
    expect(sessionDeletionHeader).toContain("Max-Age=0");
    expect(sessionDeletionHeader).toContain("Path=/");
  });
});
