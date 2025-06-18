import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CookieOptions,
  deleteChunkedCookie,
  getChunkedCookie,
  RequestCookies,
  ResponseCookies,
  setChunkedCookie
} from "./cookies.js";

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

      expect(resCookies.set).toHaveBeenCalledTimes(1);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      expect(reqCookies.set).toHaveBeenCalledTimes(1);
      expect(reqCookies.set).toHaveBeenCalledWith(name, value);
    });

    it("should split cookie into chunks when value exceeds max size", () => {
      const name = "largeCookie";
      const options = { path: "/" } as CookieOptions;

      // Create a large string (8000 bytes)
      const largeValue = "a".repeat(8000);

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      // Should create 3 chunks (8000 / 3500 ≈ 2.3, rounded up to 3)
      expect(resCookies.set).toHaveBeenCalledTimes(3);
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

      expect(resCookies.set).toHaveBeenCalledTimes(1);
      expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      expect(reqCookies.set).toHaveBeenCalledTimes(1);
      expect(reqCookies.set).toHaveBeenCalledWith(name, value);
      expect(reqCookies.delete).toHaveBeenCalledTimes(3);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__0`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__1`);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}__2`);
    });

    it("should clear existing single cookies when setting a chunked cookie", () => {
      const name = "testCookie";
      const value = "small value";

      cookieStore.set(`${name}`, value);

      // Create a large string (8000 bytes)
      const largeValue = "a".repeat(8000);
      const options = { path: "/" } as CookieOptions;

      setChunkedCookie(name, largeValue, options, reqCookies, resCookies);

      expect(reqCookies.delete).toHaveBeenCalledTimes(1);
      expect(reqCookies.delete).toHaveBeenCalledWith(`${name}`);
      expect(resCookies.set).toHaveBeenCalledTimes(3);
      expect(reqCookies.set).toHaveBeenCalledTimes(3);
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

      expect(resCookies.set).toHaveBeenCalledTimes(1);
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

      expect(resCookies.set).toHaveBeenCalledTimes(3); // 3 chunks
      expect(resCookies.set).toHaveBeenNthCalledWith(
        1,
        `${name}__0`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        2,
        `${name}__1`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        3,
        `${name}__2`,
        expect.any(String),
        expect.objectContaining({ domain: "example.com" })
      );
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

      expect(resCookies.set).toHaveBeenCalledTimes(1);
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

      expect(resCookies.set).toHaveBeenCalledTimes(3); // 3 chunks
      expect(resCookies.set).toHaveBeenNthCalledWith(
        1,
        `${name}__0`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        2,
        `${name}__1`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        3,
        `${name}__2`,
        expect.any(String),
        expectedOptions
      );
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

      expect(resCookies.set).toHaveBeenCalledTimes(1);
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

      expect(resCookies.set).toHaveBeenCalledTimes(3); // 3 chunks
      expect(resCookies.set).toHaveBeenNthCalledWith(
        1,
        `${name}__0`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        2,
        `${name}__1`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenNthCalledWith(
        3,
        `${name}__2`,
        expect.any(String),
        expectedOptions
      );
      expect(resCookies.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({ maxAge: 3600 })
      );
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

        expect(resCookies.delete).toHaveBeenCalledWith(name);
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

        // Should delete main cookie and 3 chunks
        expect(resCookies.delete).toHaveBeenCalledTimes(4);
        expect(resCookies.delete).toHaveBeenCalledWith(name);
        expect(resCookies.delete).toHaveBeenCalledWith(`${name}__0`);
        expect(resCookies.delete).toHaveBeenCalledWith(`${name}__1`);
        expect(resCookies.delete).toHaveBeenCalledWith(`${name}__2`);
        // Should not delete unrelated cookies
        expect(resCookies.delete).not.toHaveBeenCalledWith("otherCookie");
      });
    });

    describe("Edge Cases", () => {
      it("should handle empty values correctly", () => {
        const name = "emptyCookie";
        const value = "";
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        expect(resCookies.set).toHaveBeenCalledTimes(1);
        expect(resCookies.set).toHaveBeenCalledWith(name, value, options);
      });

      it("should handle values at the exact chunk boundary", () => {
        const name = "boundaryValueCookie";
        const value = "a".repeat(3500); // Exactly MAX_CHUNK_SIZE
        const options = { path: "/" } as CookieOptions;

        setChunkedCookie(name, value, options, reqCookies, resCookies);

        // Should still fit in one cookie
        expect(resCookies.set).toHaveBeenCalledTimes(1);
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

        expect(resCookies.set).toHaveBeenCalledTimes(expectedChunks);

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
