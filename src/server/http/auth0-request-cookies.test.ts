import { RequestCookies } from "@edge-runtime/cookies";
import { describe, expect, it } from "vitest";

import { Auth0RequestCookies } from "./auth0-request-cookies.js";

describe("Auth0RequestCookies", () => {
  describe("get()", () => {
    it("should retrieve a cookie by name", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123; theme=dark" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const cookie = auth0Cookies.get("session");

      expect(cookie).toEqual({ name: "session", value: "abc123" });
    });

    it("should return undefined for non-existent cookie", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const cookie = auth0Cookies.get("nonexistent");

      expect(cookie).toBeUndefined();
    });

    it("should handle cookies with special characters in value", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc%20123%2Fdef" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const cookie = auth0Cookies.get("session");

      expect(cookie?.value).toBe("abc 123/def");
    });

    it("should handle cookies with equals sign in value", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "jwt=eyJhbGc=value" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const cookie = auth0Cookies.get("jwt");

      expect(cookie?.value).toContain("=");
    });

    it("should handle empty cookie string", () => {
      const cookies = new RequestCookies(new Headers({ cookie: "" }));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const cookie = auth0Cookies.get("session");

      expect(cookie).toBeUndefined();
    });
  });

  describe("getAll()", () => {
    it("should retrieve all cookies", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123; theme=dark; lang=en" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const allCookies = auth0Cookies.getAll();

      expect(allCookies).toHaveLength(3);
      expect(allCookies).toEqual(
        expect.arrayContaining([
          { name: "session", value: "abc123" },
          { name: "theme", value: "dark" },
          { name: "lang", value: "en" }
        ])
      );
    });

    it("should return empty array when no cookies", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const allCookies = auth0Cookies.getAll();

      expect(allCookies).toEqual([]);
    });

    it("should return array of objects with name and value", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const allCookies = auth0Cookies.getAll();

      expect(allCookies).toHaveLength(1);
      expect(allCookies[0]).toHaveProperty("name");
      expect(allCookies[0]).toHaveProperty("value");
    });

    it("should handle chunked cookies from large sessions", () => {
      const cookies = new RequestCookies(
        new Headers({
          cookie: "session__0=chunk1; session__1=chunk2; session__2=chunk3"
        })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const allCookies = auth0Cookies.getAll();

      expect(allCookies.length).toBeGreaterThanOrEqual(3);
      expect(allCookies.map((c) => c.name)).toContain("session__0");
      expect(allCookies.map((c) => c.name)).toContain("session__1");
      expect(allCookies.map((c) => c.name)).toContain("session__2");
    });
  });

  describe("has()", () => {
    it("should return true if cookie exists", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(auth0Cookies.has("session")).toBe(true);
    });

    it("should return false if cookie does not exist", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(auth0Cookies.has("nonexistent")).toBe(false);
    });

    it("should be case-sensitive", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "Session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(auth0Cookies.has("Session")).toBe(true);
      expect(auth0Cookies.has("session")).toBe(false);
    });

    it("should return false for empty cookie jar", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(auth0Cookies.has("any")).toBe(false);
    });
  });

  describe("set()", () => {
    it("should set a cookie value", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("newcookie", "value123");

      expect(auth0Cookies.has("newcookie")).toBe(true);
      expect(auth0Cookies.get("newcookie")).toEqual({
        name: "newcookie",
        value: "value123"
      });
    });

    it("should update existing cookie", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=old" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("session", "new");

      expect(auth0Cookies.get("session")).toEqual({
        name: "session",
        value: "new"
      });
    });

    it("should handle cookie values with special characters", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("token", "eyJhbGc=");

      expect(auth0Cookies.get("token")?.value).toBe("eyJhbGc=");
    });

    it("should handle empty cookie value", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("empty", "");

      expect(auth0Cookies.get("empty")).toEqual({
        name: "empty",
        value: ""
      });
    });

    it("should enable read-after-write in middleware", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("session", "new_value");

      // Should be able to read the value immediately
      expect(auth0Cookies.get("session")).toEqual({
        name: "session",
        value: "new_value"
      });
    });
  });

  describe("delete()", () => {
    it("should delete a cookie", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.delete("session");

      expect(auth0Cookies.has("session")).toBe(false);
      expect(auth0Cookies.get("session")).toBeUndefined();
    });

    it("should handle deleting non-existent cookie", () => {
      const cookies = new RequestCookies(new Headers({}));
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(() => {
        auth0Cookies.delete("nonexistent");
      }).not.toThrow();
    });

    it("should not affect other cookies", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123; theme=dark" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.delete("session");

      expect(auth0Cookies.has("theme")).toBe(true);
      expect(auth0Cookies.get("theme")).toEqual({
        name: "theme",
        value: "dark"
      });
    });

    it("should handle deleting chunked cookies", () => {
      const cookies = new RequestCookies(
        new Headers({
          cookie: "session__0=chunk1; session__1=chunk2; other=value"
        })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.delete("session__0");

      expect(auth0Cookies.has("session__0")).toBe(false);
      expect(auth0Cookies.has("other")).toBe(true);
    });
  });

  describe("constructor", () => {
    it("should accept RequestCookies", () => {
      const cookies = new RequestCookies(new Headers({}));

      expect(() => {
        new Auth0RequestCookies(cookies);
      }).not.toThrow();
    });

    it("should store reference to cookies", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "session=abc123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      expect(auth0Cookies.has("session")).toBe(true);
    });
  });

  describe("integration scenarios", () => {
    it("should retrieve session cookie for authentication", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "auth0_session=session_token_123" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const sessionCookie = auth0Cookies.get("auth0_session");

      expect(sessionCookie).toEqual({
        name: "auth0_session",
        value: "session_token_123"
      });
    });

    it("should handle multiple auth-related cookies", () => {
      const cookies = new RequestCookies(
        new Headers({
          cookie:
            "auth0_session=token1; auth0_nonce=nonce123; auth0_state=state456"
        })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      const allCookies = auth0Cookies.getAll();

      expect(allCookies).toHaveLength(3);
      expect(allCookies.map((c) => c.name)).toContain("auth0_session");
      expect(allCookies.map((c) => c.name)).toContain("auth0_nonce");
      expect(allCookies.map((c) => c.name)).toContain("auth0_state");
    });

    it("should handle cookie update scenario", () => {
      const cookies = new RequestCookies(
        new Headers({ cookie: "auth0_session=old_token" })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.set("auth0_session", "new_token");

      expect(auth0Cookies.get("auth0_session")).toEqual({
        name: "auth0_session",
        value: "new_token"
      });
    });

    it("should handle cookie cleanup on logout", () => {
      const cookies = new RequestCookies(
        new Headers({
          cookie: "auth0_session=token; auth0_nonce=nonce; preferences=dark"
        })
      );
      const auth0Cookies = new Auth0RequestCookies(cookies);

      auth0Cookies.delete("auth0_session");
      auth0Cookies.delete("auth0_nonce");

      expect(auth0Cookies.has("auth0_session")).toBe(false);
      expect(auth0Cookies.has("auth0_nonce")).toBe(false);
      expect(auth0Cookies.has("preferences")).toBe(true);
    });
  });
});
