import { describe, expect, it } from "vitest";

import {
  ensureNoLeadingSlash,
  ensureTrailingSlash,
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
});
