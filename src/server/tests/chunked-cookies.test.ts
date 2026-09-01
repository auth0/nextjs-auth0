import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test-fixtures/utils.js";
import { SessionData } from "../../types/index.js";
import {
  CookieOptions,
  decrypt,
  deleteChunkedCookie,
  encrypt,
  getChunkedCookie,
  RequestCookies,
  ResponseCookies,
  setChunkedCookie
} from "../cookies/index.js";

// Create mock implementation for RequestCookies and ResponseCookies
const createMocks = () => {
  const cookieStore = new Map();

  const reqCookies = {
    get: vi.fn((...args) => {
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      if (cookieStore.has(name)) {
        return { name, value: cookieStore.get(name) };
      }
      return undefined;
    }),
    getAll: vi.fn((...args) => {
      if (args.length === 0) {
        return Array.from(cookieStore.entries()).map(([name, value]) => ({
          name,
          value
        }));
      }
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      return cookieStore.has(name)
        ? [{ name, value: cookieStore.get(name) }]
        : [];
    }),
    has: vi.fn((name) => cookieStore.has(name)),
    set: vi.fn((...args) => {
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      const value = typeof args[0] === "string" ? args[1] : args[0].value;
      cookieStore.set(name, value);
      return reqCookies;
    }),
    delete: vi.fn((names) => {
      if (Array.isArray(names)) {
        return names.map((name) => cookieStore.delete(name));
      }
      return cookieStore.delete(names);
    }),
    clear: vi.fn(() => {
      cookieStore.clear();
      return reqCookies;
    }),
    get size() {
      return cookieStore.size;
    },
    [Symbol.iterator]: vi.fn(() => cookieStore.entries())
  };

  const resCookies = {
    get: vi.fn((...args) => {
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      if (cookieStore.has(name)) {
        return { name, value: cookieStore.get(name) };
      }
      return undefined;
    }),
    getAll: vi.fn((...args) => {
      if (args.length === 0) {
        return Array.from(cookieStore.entries()).map(([name, value]) => ({
          name,
          value
        }));
      }
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      return cookieStore.has(name)
        ? [{ name, value: cookieStore.get(name) }]
        : [];
    }),
    has: vi.fn((name) => cookieStore.has(name)),
    set: vi.fn((...args) => {
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      const value = typeof args[0] === "string" ? args[1] : args[0].value;
      cookieStore.set(name, value);
      return resCookies;
    }),
    delete: vi.fn((...args) => {
      const name = typeof args[0] === "string" ? args[0] : args[0].name;
      cookieStore.delete(name);
      return resCookies;
    }),
    toString: vi.fn(() => {
      return Array.from(cookieStore.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    })
  };

  return { reqCookies, resCookies, cookieStore };
};

describe("Chunked Cookie Utils", () => {
  let reqCookies: RequestCookies;
  let resCookies: ResponseCookies;
  let cookieStore: Map<any, any>;

  beforeEach(() => {
    const mocks = createMocks();
    reqCookies = mocks.reqCookies;
    resCookies = mocks.resCookies;
    cookieStore = mocks.cookieStore;

    // Spy on console.warn
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("setChunkedCookie", () => {
    it("should set a single cookie when value is small enough", () => {
      const name = "testCookie";
      const value = "small value";
      const options = { path: "/" } as CookieOptions;

      setChunkedCookie(name, value, options, reqCookies, resCookies);

      // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__0`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__1`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__2`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(reqCookies.set).toHaveBeenCalledTimes(1);
      expect(reqCookies.set).toHaveBeenCalledWith(name, value);
      // reqCookies.delete called 5 times for indices 0-4
      expect(reqCookies.delete).toHaveBeenCalledTimes(5);
    });

    it("should split cookie into chunks when value exceeds max size", () => {
      const name = "largeCookie";
      const options = { path: "/" } as CookieOptions;

      // Create a large string (8000 bytes)
      const largeValue = "a".repeat(8000);

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // resCookies.set called 6 times:
      // 3 calls to set the chunks (__0, __1, __2)
      // 2 calls to delete higher indices (__3, __4)
      // 1 call to delete the base cookie
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(reqCookies.set).toHaveBeenCalledTimes(3);

      // Check first chunk
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__0`,
        largeValue.slice(0, 3500),
        options
      );

      // Check second chunk
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__1`,
        largeValue.slice(3500, 7000),
        options
      );

      // Check third chunk
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__2`,
        largeValue.slice(7000),
        options
      );

      // Check deletion of unused chunk indices and base cookie
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(name, "", {
        maxAge: 0,
        path: "/"
      });

      // reqCookies.delete called 3 times: __3, __4, and base name
      expect(reqCookies.delete).toHaveBeenCalledTimes(3);
    });

    it("should clear existing chunked cookies when setting a single cookie", () => {
      const name = "testCookie";
      const value = "small value";
      const options = { path: "/" } as CookieOptions;

      const chunk0 = "chunk0 value";
      const chunk1 = "chunk1 value";
      const chunk2 = "chunk2 value";

      cookieStore.set(`${name}__1`, chunk1);
      cookieStore.set(`${name}__0`, chunk0);
      cookieStore.set(`${name}__2`, chunk2);

      setChunkedCookie(name, value, options, reqCookies, resCookies);

      // resCookies.set called 6 times:
      // 1 set of main cookie, then 5 deletes of deterministic indices 0-4
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__0`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__1`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__2`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(reqCookies.set).toHaveBeenCalledTimes(1);
      expect(reqCookies.set).toHaveBeenCalledWith(name, value);
      // reqCookies.delete called 5 times for deterministic indices 0-4
      expect(reqCookies.delete).toHaveBeenCalledTimes(5);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__0`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__1`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__2`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__3`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__4`);
    });

    it("should clear existing single cookies when setting a chunked cookie", () => {
      const name = "testCookie";
      const value = "small value";

      cookieStore.set(`${name}`, value);

      // Create a large string (8000 bytes)
      const largeValue = "a".repeat(8000);
      const options = { path: "/" } as CookieOptions;

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // reqCookies.delete called 3 times: once for base name, then __3, __4
      expect(reqCookies.delete).toHaveBeenCalledTimes(3);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__3`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__4`);

      // resCookies.set called 6 times:
      // 3 calls to set the chunks (__0, __1, __2)
      // 2 calls to delete higher indices (__3, __4)
      // 1 call to delete the base cookie
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__0`,
        largeValue.slice(0, 3500),
        options
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__1`,
        largeValue.slice(3500, 7000),
        options
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__2`,
        largeValue.slice(7000),
        options
      );
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        maxAge: 0,
        path: "/"
      });
      expect(resCookies.set).toHaveBeenCalledWith(name, "", {
        maxAge: 0,
        path: "/"
      });
      expect(reqCookies.set).toHaveBeenCalledTimes(3);
    });

    it("deletes higher-index chunks even when absent from the request snapshot (cross-tab orphan)", () => {
      // A concurrent tab wrote __session__2, but this request's reqCookies only
      // shows __0/__1. The deterministic sweep must still issue a deletion for
      // __2 (and the rest of the range) so no chunk is left orphaned.
      const name = "__session";
      const options = { path: "/" } as CookieOptions;

      // reqCookies snapshot is missing the concurrently-written __2 chunk.
      cookieStore.set(`${name}__0`, "old0");
      cookieStore.set(`${name}__1`, "old1");

      // New value is small → single-cookie path, which sweeps chunk indices 0..4.
      setChunkedCookie(name, "small", options, reqCookies, resCookies);

      // A deletion is issued for every index in the deterministic range,
      // including __2 which was never in reqCookies.
      for (let i = 0; i < 5; i++) {
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__${i}`, "", {
          maxAge: 0,
          path: "/"
        });
      }
    });

    it("should clean up unused chunks when cookie shrinks", () => {
      const name = "testCookie";
      const options = { path: "/" } as CookieOptions;

      const chunk0 = "chunk0 value";
      const chunk1 = "chunk1 value";
      const chunk2 = "chunk2 value";
      const chunk3 = "chunk3 value";
      const chunk4 = "chunk4 value";

      cookieStore.set(`${name}__1`, chunk1);
      cookieStore.set(`${name}__0`, chunk0);
      cookieStore.set(`${name}__2`, chunk2);
      cookieStore.set(`${name}__3`, chunk3);
      cookieStore.set(`${name}__4`, chunk4);

      const largeValue = "a".repeat(8000);
      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // It is called 3 times.
      // 2 times for the chunks
      // 1 time for the non chunked cookie
      expect(reqCookies.delete).toHaveBeenCalledTimes(3);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__3`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__4`);
      expect(reqCookies.delete).toHaveBeenCalledWith(name);
    });

    it("clears high-index chunks (>= MAX_CHUNKS) when a session that grew past MAX_CHUNKS shrinks", () => {
      // Regression: a session that once wrote __session__5 (or higher) and
      // then shrinks would otherwise leave the high-index chunk orphaned,
      // because the deterministic sweep only covers __0..__4. The snapshot
      // must extend the sweep to cover indices seen in the request.
      const name = "__session";
      const options = { path: "/" } as CookieOptions;

      // Seed a 6-chunk state (as if a prior write produced them).
      for (let i = 0; i < 6; i++) {
        cookieStore.set(`${name}__${i}`, `chunk${i}`);
      }

      // Shrink: write a value that fits in ~2 chunks.
      const shrunkValue = "a".repeat(7000);
      setChunkedCookie(name, shrunkValue, options, reqCookies, resCookies);

      // The high-index chunk written before the shrink must be deleted,
      // otherwise it stays in the browser and poisons subsequent reads.
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__5`,
        "",
        expect.objectContaining({ maxAge: 0 })
      );
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__5`);
    });

    // New tests for domain and transient options
    it("should set the domain property for a single cookie", () => {
      const name = "domainCookie";
      const value = "small value";
      const options: CookieOptions = {
        path: "/",
        domain: "example.com",
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };

      setChunkedCookie(name, value, options, reqCookies, resCookies);

      // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(
        name,
        value,
        expect.objectContaining({ domain: "example.com" })
      );
    });

    it("should set the domain property for chunked cookies", () => {
      const name = "largeDomainCookie";
      const largeValue = "a".repeat(8000);
      const options: CookieOptions = {
        path: "/",
        domain: "example.com",
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // resCookies.set called 6 times:
      // 3 calls to set the chunks (__0, __1, __2)
      // 2 calls to delete higher indices (__3, __4)
      // 1 call to delete the base cookie
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__0`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__1`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__2`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        domain: "example.com",
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        domain: "example.com",
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(name, "", {
        domain: "example.com",
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
    });

    it("should omit maxAge for a single transient cookie", () => {
      const name = "transientCookie";
      const value = "small value";
      const options: CookieOptions = {
        path: "/",
        maxAge: 3600,
        transient: true,
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };
      const expectedOptions = { ...options };
      delete expectedOptions.maxAge; // maxAge should be removed
      delete expectedOptions.transient; // transient flag itself is not part of the cookie options

      setChunkedCookie(name, value, options, reqCookies, resCookies);

      // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, expectedOptions);
      expect(resCookies.set).not.toHaveBeenCalledWith(
        name,
        value,
        expect.objectContaining({ maxAge: 3600 })
      );
    });

    it("should omit maxAge for chunked transient cookies", () => {
      const name = "largeTransientCookie";
      const largeValue = "a".repeat(8000);
      const options: CookieOptions = {
        path: "/",
        maxAge: 3600,
        transient: true,
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };
      const expectedOptions = { ...options };
      delete expectedOptions.maxAge; // maxAge should be removed
      delete expectedOptions.transient; // transient flag itself is not part of the cookie options

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // resCookies.set called 6 times:
      // 3 calls to set the chunks (__0, __1, __2)
      // 2 calls to delete higher indices (__3, __4)
      // 1 call to delete the base cookie
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__0`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__1`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__2`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(name, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).not.toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({ maxAge: 3600 })
      );
    });

    it("should include maxAge for a single non-transient cookie", () => {
      const name = "nonTransientCookie";
      const value = "small value";
      const options: CookieOptions = {
        path: "/",
        maxAge: 3600,
        transient: false,
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };
      const expectedOptions = { ...options };
      delete expectedOptions.transient; // transient flag itself is not part of the cookie options

      setChunkedCookie(name, value, options, reqCookies, resCookies);

      // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, expectedOptions);
      expect(resCookies.set).toHaveBeenCalledWith(
        name,
        value,
        expect.objectContaining({ maxAge: 3600 })
      );
    });

    it("should include maxAge for chunked non-transient cookies", () => {
      const name = "largeNonTransientCookie";
      const largeValue = "a".repeat(8000);
      const options: CookieOptions = {
        path: "/",
        maxAge: 3600,
        transient: false,
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      };
      const expectedOptions = { ...options };
      delete expectedOptions.transient; // transient flag itself is not part of the cookie options

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // resCookies.set called 6 times:
      // 3 calls to set the chunks (__0, __1, __2)
      // 2 calls to delete higher indices (__3, __4)
      // 1 call to delete the base cookie
      expect(resCookies.set).toHaveBeenCalledTimes(6);
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__0`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__1`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        `${name}__2`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
      expect(resCookies.set).toHaveBeenCalledWith(name, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: true
      });
    });

    describe("getChunkedCookie", () => {
      it("should return undefined if no cookie or chunks are found", () => {
        const result = getChunkedCookie("nonexistent", reqCookies, false);
        expect(result).toBeUndefined();
      });

      it("should retrieve a single non-chunked cookie", () => {
        const name = "singleCookie";
        const value = "single value";
        cookieStore.set(name, value);

        const result = getChunkedCookie(name, reqCookies, false);

        expect(result).toBe(value);

        expect(reqCookies.get).toHaveBeenCalledWith(name);
      });

      it("should retrieve and combine chunked cookies", () => {
        const name = "chunkedCookie";
        const chunk0 = "chunk0 value";
        const chunk1 = "chunk1 value";
        const chunk2 = "chunk2 value";

        // Set in reverse order to test sorting
        cookieStore.set(`${name}__1`, chunk1);
        cookieStore.set(`${name}__0`, chunk0);
        cookieStore.set(`${name}__2`, chunk2);

        expect(getChunkedCookie(name, reqCookies, false)).toBe(
          `${chunk0}${chunk1}${chunk2}`
        );
      });

      it("should retrieve and combine chunked cookies using legacy format", () => {
        const name = "legacyChunkedCookie";
        const chunk0 = "legacy chunk0 value";
        const chunk1 = "legacy chunk1 value";

        // Set in reverse order to test sorting
        cookieStore.set(`${name}.1`, chunk1);
        cookieStore.set(`${name}.0`, chunk0);

        expect(getChunkedCookie(name, reqCookies, true)).toBe(
          `${chunk0}${chunk1}`
        );
      });

      it("should return undefined when chunks are not in a complete sequence", () => {
        const name = "incompleteCookie";

        // Add incomplete chunks (missing chunk1)
        cookieStore.set(`${name}__0`, "chunk0");
        cookieStore.set(`${name}__2`, "chunk2");

        const result = getChunkedCookie(name, reqCookies, false);

        expect(result).toBeUndefined();
        expect(console.warn).toHaveBeenCalled();
      });
    });

    describe("deleteChunkedCookie", () => {
      it("should delete the regular cookie", () => {
        const name = "regularCookie";
        cookieStore.set(name, "regular value");

        deleteChunkedCookie(name, reqCookies, resCookies);

        expect(resCookies.set).toHaveBeenCalledWith(name, "", {
          maxAge: 0
        });
      });

      it("should delete all chunks of a cookie", () => {
        const name = "chunkedCookie";

        // Add chunks
        cookieStore.set(`${name}__0`, "chunk0");
        cookieStore.set(`${name}__1`, "chunk1");
        cookieStore.set(`${name}__2`, "chunk2");

        // Add unrelated cookie
        cookieStore.set("otherCookie", "other value");

        deleteChunkedCookie(name, reqCookies, resCookies);

        // Should delete main cookie and deterministic range of chunks (0-4)
        expect(resCookies.set).toHaveBeenCalledTimes(6);
        expect(resCookies.set).toHaveBeenCalledWith(name, "", {
          maxAge: 0
        });
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__0`, "", {
          maxAge: 0
        });
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__1`, "", {
          maxAge: 0
        });
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__2`, "", {
          maxAge: 0
        });
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__3`, "", {
          maxAge: 0
        });
        expect(resCookies.set).toHaveBeenCalledWith(`${name}__4`, "", {
          maxAge: 0
        });
        // Should not delete unrelated cookies
        expect(resCookies.set).not.toHaveBeenCalledWith("otherCookie", "", {
          maxAge: 0
        });
      });

      it("deletes high-index chunks (>= MAX_CHUNKS) present in the request snapshot", () => {
        // Regression: a session that once grew past MAX_CHUNKS would leave
        // __session__5+ orphaned on logout, because the deterministic sweep
        // only covers __0..__4. The snapshot must extend the sweep.
        const name = "__session";
        for (let i = 0; i < 6; i++) {
          cookieStore.set(`${name}__${i}`, `chunk${i}`);
        }

        deleteChunkedCookie(name, reqCookies, resCookies);

        expect(resCookies.set).toHaveBeenCalledWith(`${name}__5`, "", {
          maxAge: 0
        });
      });
    });

    describe("Edge Cases", () => {
      it("should handle empty values correctly", () => {
        const name = "emptyCookie";
        const value = "";
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
        expect(resCookies.set).toHaveBeenCalledTimes(6);
        expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      });

      it("should handle values at the exact chunk boundary", () => {
        const name = "boundaryValueCookie";
        const value = "a".repeat(3500); // Exactly MAX_CHUNK_SIZE
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        // Should still fit in one cookie, but deterministic deletes still happen
        // resCookies.set called 6 times: 1 set + 5 deletes for indices 0-4
        expect(resCookies.set).toHaveBeenCalledTimes(6);
        expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      });

      it("should handle special characters in cookie values", () => {
        const name = "specialCharCookie";
        const value =
          '{"special":"characters","with":"quotation marks","and":"😀 emoji"}';
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        expect(resCookies.set).toHaveBeenCalledWith(name, value, options);

        // Setup for retrieval
        cookieStore.set(name, value);

        const result = getChunkedCookie(name, reqCookies);
        expect(result).toBe(value);
      });

      it("should handle multi-byte characters correctly", () => {
        const name = "multiByteCookie";
        // Create a test string with multi-byte characters (emojis)
        const value = "Hello 😀 world 🌍 with emojis 🎉";
        const options = { path: "/" } as CookieOptions;

        // Store the cookie
        setChunkedCookie(name, value, options, reqCookies, resCookies);

        // For the retrieval test, manually set up the cookies
        // We're testing the retrieval functionality, not the chunking itself
        cookieStore.clear();
        cookieStore.set(name, value);

        // Verify retrieval works correctly with multi-byte characters
        const result = getChunkedCookie(name, reqCookies);
        expect(result).toBe(value);

        // Verify emoji characters were preserved
        expect(result).toContain("😀");
        expect(result).toContain("🌍");
        expect(result).toContain("🎉");
      });

      it("should handle very large cookies properly", () => {
        const name = "veryLargeCookie";
        const value = "a".repeat(10000); // Will create multiple chunks
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        // Get chunks count (10000 / 3500 ≈ 2.86, so we need 3 chunks)
        const expectedChunks = Math.ceil(10000 / 3500);

        // resCookies.set called 6 times:
        // 3 calls to set the chunks
        // 2 calls to delete higher indices (__3, __4)
        // 1 call to delete the base cookie
        expect(resCookies.set).toHaveBeenCalledTimes(6);

        // Clear and set up cookies for retrieval test
        cookieStore.clear();

        // Setup for getChunkedCookie retrieval
        for (let i = 0; i < expectedChunks; i++) {
          const start = i * 3500;
          const end = Math.min((i + 1) * 3500, 10000);
          cookieStore.set(`${name}__${i}`, value.slice(start, end));
        }

        const result = getChunkedCookie(name, reqCookies);
        expect(result).toBe(value);
        expect(result!.length).toBe(10000);
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Regression #2595: MCD backfill causes session chunking at boundary
//
// When getSessionWithDomainCheck() unconditionally backfills `internal.mcd`
// in static mode, sessions near MAX_CHUNK_SIZE cross the threshold and get
// chunked on every middleware pass. These tests verify the boundary behavior.
//
// @see https://github.com/auth0/nextjs-auth0/issues/2595
// ---------------------------------------------------------------------------

const MAX_CHUNK_SIZE = 3500;

/**
 * Build a pre-MCD session that, when encrypted, lands just below the 3500-byte
 * chunking boundary. The access token is the primary size lever — matches the
 * customer's `audience` config where the AT is stored in the session cookie.
 */
function buildPreMcdSession(accessTokenLength: number): SessionData {
  return {
    user: {
      sub: "auth0|507f1f77bcf86cd799439011",
      name: "Test User With A Reasonably Long Display Name",
      email: "testuser.with.long.email@example-organization.com",
      email_verified: true,
      nickname: "testuser.with.long.nickname",
      updated_at: "2026-04-13T00:00:00.000Z"
    },
    tokenSet: {
      accessToken: "eyJhbGciOiJSUzI1NiJ9." + "A".repeat(accessTokenLength),
      idToken:
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
        btoa(
          JSON.stringify({
            iss: "https://example.auth0.com/",
            sub: "auth0|507f1f77bcf86cd799439011",
            aud: "test-client-id",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000)
          })
        ) +
        ".fake-signature",
      token_type: "Bearer",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scope: "openid profile email"
    },
    internal: {
      sid: "session-id-abcdef1234567890",
      createdAt: Math.floor(Date.now() / 1000)
    }
    // NOTE: no `internal.mcd` — this is a pre-MCD session
  };
}

/** Find an access token length that puts the encrypted session just below the chunking threshold. */
async function findBoundarySession(secret: string): Promise<{
  session: SessionData;
  encrypted: string;
  size: number;
}> {
  let atLen = 1600;
  let session: SessionData = {} as SessionData;
  let encrypted: string = "";
  let size: number = 0;

  let found = false;
  for (let attempt = 0; attempt < 50 && !found; attempt++) {
    session = buildPreMcdSession(atLen);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    encrypted = await encrypt(session, secret, exp);
    size = new TextEncoder().encode(encrypted).length;
    if (size < 3400) atLen += 30;
    else if (size >= MAX_CHUNK_SIZE) atLen -= 10;
    else found = true;
  }

  return { session, encrypted, size };
}

describe("Regression #2595: MCD backfill session chunking at boundary", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  it("backfill pushes encrypted session past MAX_CHUNK_SIZE", async () => {
    const { session, size: preSize } = await findBoundarySession(secret);

    expect(preSize).toBeGreaterThanOrEqual(3400);
    expect(preSize).toBeLessThan(MAX_CHUNK_SIZE);

    // Simulate backfill
    session.internal = session.internal || {};
    (session.internal as any).mcd = {
      domain: "example.auth0.com",
      issuer: "https://example.auth0.com/"
    };

    const postEncrypted = await encrypt(
      session,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );
    const postSize = new TextEncoder().encode(postEncrypted).length;

    expect(postSize).toBeGreaterThan(MAX_CHUNK_SIZE);
  });

  it("setChunkedCookie produces chunks when backfilled session exceeds threshold", async () => {
    const session = buildPreMcdSession(1800);
    (session.internal as any).mcd = {
      domain: "example.auth0.com",
      issuer: "https://example.auth0.com/"
    };

    const encrypted = await encrypt(
      session,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );
    expect(new TextEncoder().encode(encrypted).length).toBeGreaterThan(
      MAX_CHUNK_SIZE
    );

    const { cookieStore, reqCookies, resCookies } = createMocks();
    setChunkedCookie(
      "__session",
      encrypted,
      { path: "/", sameSite: "lax" as const, httpOnly: true, secure: true },
      reqCookies as unknown as RequestCookies,
      resCookies as unknown as ResponseCookies
    );

    expect(cookieStore.has("__session__0")).toBe(true);
    expect(cookieStore.has("__session__1")).toBe(true);
    expect(cookieStore.has("__session")).toBe(false);
  });

  it("getChunkedCookie reassembles chunked session with full decrypt round-trip", async () => {
    const session = buildPreMcdSession(1800);
    (session.internal as any).mcd = {
      domain: "example.auth0.com",
      issuer: "https://example.auth0.com/"
    };

    const encrypted = await encrypt(
      session,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );

    const { reqCookies, resCookies } = createMocks();
    setChunkedCookie(
      "__session",
      encrypted,
      { path: "/", sameSite: "lax" as const, httpOnly: true, secure: true },
      reqCookies as unknown as RequestCookies,
      resCookies as unknown as ResponseCookies
    );

    const reassembled = getChunkedCookie(
      "__session",
      reqCookies as unknown as RequestCookies
    );
    expect(reassembled).toBe(encrypted);

    const decrypted = await decrypt<SessionData>(reassembled!, secret);
    expect(decrypted).toBeDefined();
    expect(decrypted!.payload.user.sub).toBe("auth0|507f1f77bcf86cd799439011");
    expect((decrypted!.payload.internal as any).mcd.domain).toBe(
      "example.auth0.com"
    );
  });

  it("getChunkedCookie falls through to chunks when __session is empty string", () => {
    const { cookieStore, reqCookies } = createMocks();
    cookieStore.set("__session", "");
    cookieStore.set("__session__0", "chunk0");
    cookieStore.set("__session__1", "chunk1");

    const result = getChunkedCookie(
      "__session",
      reqCookies as unknown as RequestCookies
    );
    expect(result).toBe("chunk0chunk1");
  });

  it("getChunkedCookie returns original value when __session is non-empty alongside chunks", async () => {
    const session = buildPreMcdSession(1800);
    const encrypted = await encrypt(
      session,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );

    const { cookieStore, reqCookies } = createMocks();
    cookieStore.set("__session", encrypted);
    cookieStore.set("__session__0", "chunk0value");
    cookieStore.set("__session__1", "chunk1value");

    const result = getChunkedCookie(
      "__session",
      reqCookies as unknown as RequestCookies
    );
    // Non-empty __session takes precedence — returns pre-backfill session
    expect(result).toBe(encrypted);
  });

  it("full round-trip: middleware backfill+chunk then route handler reassembly", async () => {
    const {
      session,
      encrypted: originalEncrypted,
      size: _originalSize
    } = await findBoundarySession(secret);

    // Middleware: backfill + re-encrypt
    session.internal = session.internal || {};
    (session.internal as any).mcd = {
      domain: "example.auth0.com",
      issuer: "https://example.auth0.com/"
    };

    const backfilledEncrypted = await encrypt(
      session as unknown as jose.JWTPayload,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );
    expect(
      new TextEncoder().encode(backfilledEncrypted).length
    ).toBeGreaterThan(MAX_CHUNK_SIZE);

    // Middleware writes chunks
    const {
      cookieStore: mwStore,
      reqCookies: mwReq,
      resCookies: mwRes
    } = createMocks();
    mwStore.set("__session", originalEncrypted);

    setChunkedCookie(
      "__session",
      backfilledEncrypted,
      { path: "/", sameSite: "lax" as const, httpOnly: true, secure: true },
      mwReq as unknown as RequestCookies,
      mwRes as unknown as ResponseCookies
    );

    expect(mwStore.has("__session__0")).toBe(true);
    expect(mwStore.has("__session__1")).toBe(true);
    expect(mwStore.has("__session")).toBe(false);

    // Scenario A: same-request propagation (middleware store = merged store)
    const resultA = getChunkedCookie(
      "__session",
      mwReq as unknown as RequestCookies
    );
    expect(resultA).toBe(backfilledEncrypted);

    const sessionA = await decrypt<SessionData>(resultA!, secret);
    expect(sessionA!.payload.user.sub).toBe("auth0|507f1f77bcf86cd799439011");

    // Scenario B: next-request (browser sends only chunks)
    const { cookieStore: browserStore, reqCookies: browserReq } = createMocks();
    browserStore.set("__session__0", mwStore.get("__session__0")!);
    browserStore.set("__session__1", mwStore.get("__session__1")!);

    const resultB = getChunkedCookie(
      "__session",
      browserReq as unknown as RequestCookies
    );
    expect(resultB).toBe(backfilledEncrypted);
  });

  it("skipping backfill in static mode preserves session size below threshold", async () => {
    const { session, size: _size } = await findBoundarySession(secret);

    // Static mode: no backfill
    expect((session.internal as any).mcd).toBeUndefined();

    // Re-encrypt unchanged session (simulates rolling touch without backfill)
    const reEncrypted = await encrypt(
      session,
      secret,
      Math.floor(Date.now() / 1000) + 3600
    );
    const reEncryptedSize = new TextEncoder().encode(reEncrypted).length;
    expect(reEncryptedSize).toBeLessThan(MAX_CHUNK_SIZE);

    // Stays as single cookie
    const { cookieStore, reqCookies, resCookies } = createMocks();
    setChunkedCookie(
      "__session",
      reEncrypted,
      { path: "/", sameSite: "lax" as const, httpOnly: true, secure: true },
      reqCookies as unknown as RequestCookies,
      resCookies as unknown as ResponseCookies
    );

    expect(cookieStore.has("__session")).toBe(true);
    expect(cookieStore.has("__session__0")).toBe(false);
    expect(cookieStore.has("__session__1")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// End-to-end jar tests. These use the real RequestCookies / ResponseCookies
// implementations and apply Set-Cookie headers to a browser-like jar between
// writes, then assert on read via getChunkedCookie. This exercises the whole
// write → apply → read cycle, which is what a real user hits — as opposed to
// the mock-based tests above which only assert on `resCookies.set` spy calls.
// ---------------------------------------------------------------------------

/**
 * Minimal browser cookie jar: applies Set-Cookie writes from a `ResponseCookies`
 * to an in-memory store (honouring `maxAge: 0` as deletion), and produces a
 * fresh `RequestCookies` reflecting the current jar state for the next request.
 */
class BrowserJar {
  private store = new Map<string, string>();

  apply(res: ResponseCookies) {
    for (const c of res.getAll()) {
      if (c.maxAge === 0 || c.value === "") {
        this.store.delete(c.name);
      } else {
        this.store.set(c.name, c.value);
      }
    }
  }

  req(): RequestCookies {
    const headers = new Headers();
    const cookieHeader = Array.from(this.store)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
    if (cookieHeader) headers.append("cookie", cookieHeader);
    return new RequestCookies(headers);
  }

  names(): string[] {
    return Array.from(this.store.keys()).sort();
  }
}

describe("Chunked Cookie — end-to-end jar", () => {
  const OPTS: CookieOptions = {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax" as const,
    maxAge: 3600
  };

  const write = (jar: BrowserJar, name: string, value: string) => {
    const res = new ResponseCookies(new Headers());
    setChunkedCookie(name, value, OPTS, jar.req(), res);
    jar.apply(res);
    return res;
  };

  it("shrinking a 6-chunk session leaves no high-index orphan and the value reads back", () => {
    // Regression: before the getClearUpTo fix, a session that grew past
    // MAX_CHUNKS (5) then shrank would leave __session__5 orphaned in the
    // browser and getChunkedCookie would return undefined forever.
    const jar = new BrowserJar();

    // Write a value that requires 6 chunks (6 × 3500 = 21000 bytes).
    const big = "a".repeat(21000);
    write(jar, "__session", big);
    expect(jar.names()).toEqual([
      "__session__0",
      "__session__1",
      "__session__2",
      "__session__3",
      "__session__4",
      "__session__5"
    ]);

    // Shrink to a value that fits in 2 chunks (~7000 bytes).
    const small = "b".repeat(7000);
    write(jar, "__session", small);

    // No high-index orphan.
    expect(jar.names()).toEqual(["__session__0", "__session__1"]);

    // Read returns the full new value.
    const read = getChunkedCookie("__session", jar.req());
    expect(read).toBe(small);
  });

  it("logout of a 6-chunk session clears every chunk", () => {
    const jar = new BrowserJar();
    write(jar, "__session", "a".repeat(21000));
    expect(jar.names().length).toBe(6);

    const res = new ResponseCookies(new Headers());
    deleteChunkedCookie("__session", jar.req(), res, false, {
      path: "/",
      domain: undefined
    });
    jar.apply(res);

    expect(jar.names()).toEqual([]);
    expect(getChunkedCookie("__session", jar.req())).toBeUndefined();
  });

  it("residual case: concurrent-tab write above MAX_CHUNKS not in snapshot self-heals on next write", () => {
    // Tab A writes 6 chunks. Tab B starts from an older browser state showing
    // only __0 and __1 (Tab A's __2..__5 haven't reached Tab B's request yet).
    // Tab B writes a 2-chunk value. Because Tab B's snapshot doesn't reveal
    // __session__5, the sweep stops at MAX_CHUNKS (5), and __5 survives.
    // Read on THAT response is broken (getChunkedCookie sees indices [0,1,5],
    // highestIndex=5, count mismatch → undefined). The next write on this
    // connection sees __5 in its snapshot and cleans up. One bad response,
    // self-healing — not the permanent login loop from before.

    const browserJar = new BrowserJar();
    // Simulate the eventual browser state after Tab A finished.
    write(browserJar, "__session", "a".repeat(21000));

    // Tab B's stale snapshot: only __0/__1 as seen when Tab B's request started.
    const staleReqHeaders = new Headers();
    staleReqHeaders.append(
      "cookie",
      `__session__0=${browserJar.req().get("__session__0")!.value};` +
        `__session__1=${browserJar.req().get("__session__1")!.value}`
    );
    const staleReq = new RequestCookies(staleReqHeaders);

    // Tab B writes 2 chunks using its stale snapshot.
    const tabBRes = new ResponseCookies(new Headers());
    setChunkedCookie("__session", "b".repeat(7000), OPTS, staleReq, tabBRes);
    browserJar.apply(tabBRes);

    // __session__5 survives — Tab B never saw it. Confirmed orphan.
    expect(browserJar.names()).toContain("__session__5");
    // The immediate read is broken.
    expect(getChunkedCookie("__session", browserJar.req())).toBeUndefined();

    // Next write on this connection SEES __5 in the snapshot and cleans up.
    write(browserJar, "__session", "c".repeat(7000));

    expect(browserJar.names()).toEqual(["__session__0", "__session__1"]);
    expect(getChunkedCookie("__session", browserJar.req())).toBe(
      "c".repeat(7000)
    );
  });
});
