import { afterEach, describe, expect, it } from "vitest";

import {
  ensureLeadingSlash,
  ensureNoLeadingSlash,
  ensureTrailingSlash,
  normalizeWithBasePath,
  removeTrailingSlash
} from "./pathUtils.js";

describe("pathUtils", () => {
  describe("ensureTrailingSlash", () => {
    it("should add a trailing slash if not present", () => {
      expect(ensureTrailingSlash("example.com/path")).toBe("example.com/path/");
    });

    it("should not add a trailing slash if already present", () => {
      expect(ensureTrailingSlash("example.com/path/")).toBe(
        "example.com/path/"
      );
    });

    it("should return the same string if it is empty", () => {
      expect(ensureTrailingSlash("")).toBe("");
    });
  });

  describe("ensureNoLeadingSlash", () => {
    it("should remove the leading slash if present", () => {
      expect(ensureNoLeadingSlash("/example/path")).toBe("example/path");
    });

    it("should not remove the leading slash if not present", () => {
      expect(ensureNoLeadingSlash("example/path")).toBe("example/path");
    });

    it("should return the same string if it is empty", () => {
      expect(ensureNoLeadingSlash("")).toBe("");
    });
  });

  describe("removeTrailingSlash", () => {
    it("should remove the trailing slash if present", () => {
      expect(removeTrailingSlash("example.com/path/")).toBe("example.com/path");
    });

    it("should not remove the trailing slash if not present", () => {
      expect(removeTrailingSlash("example.com/path")).toBe("example.com/path");
    });

    it("should return the same string if it is empty", () => {
      expect(removeTrailingSlash("")).toBe("");
    });
  });

  describe("ensureLeadingSlash", () => {
    it("should add a leading slash if not present", () => {
      expect(ensureLeadingSlash("example/path")).toBe("/example/path");
    });

    it("should not add a leading slash if already present", () => {
      expect(ensureLeadingSlash("/example/path")).toBe("/example/path");
    });

    it("should return the same string if it is empty", () => {
      expect(ensureLeadingSlash("")).toBe("");
    });
  });

  describe("normalizeWithBasePath", () => {
    afterEach(() => {
      delete process.env.NEXT_PUBLIC_BASE_PATH;
    });

    describe("when the base path does not have a leading slash", () => {
      it("should correctly prepend the base path", () => {
        process.env.NEXT_PUBLIC_BASE_PATH = "docs";

        expect(normalizeWithBasePath("/path/to/resource")).toBe(
          "/docs/path/to/resource"
        );
      });
    });

    describe("when the base path has a leading slash", () => {
      it("should correctly prepend the base path", () => {
        process.env.NEXT_PUBLIC_BASE_PATH = "/docs";

        expect(normalizeWithBasePath("/path/to/resource")).toBe(
          "/docs/path/to/resource"
        );
      });
    });

    describe("when the base path has a trailing slash", () => {
      it("should correctly join the paths", () => {
        process.env.NEXT_PUBLIC_BASE_PATH = "/docs/";

        expect(normalizeWithBasePath("/path/to/resource")).toBe(
          "/docs/path/to/resource"
        );
      });
    });

    describe("when the base path is empty", () => {
      it("should return the original path", () => {
        process.env.NEXT_PUBLIC_BASE_PATH = "";

        expect(normalizeWithBasePath("/path/to/resource")).toBe(
          "/path/to/resource"
        );
      });
    });

    describe("when the base path is undefined", () => {
      it("should return the same path if no base path is set", () => {
        delete process.env.NEXT_PUBLIC_BASE_PATH;

        expect(normalizeWithBasePath("/path/to/resource")).toBe(
          "/path/to/resource"
        );
      });
    });
  });
});
