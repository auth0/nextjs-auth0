import { describe, expect, it } from "vitest";

import { mergeAuthorizationParamsIntoSearchParams } from "./authorization-params-helpers.js";

describe("authorization-params-helpers", () => {
  describe("mergeAuthorizationParamsIntoSearchParams", () => {
    it("should merge both sides", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { a: 1 },
        { b: 2 }
      );
      expect(searchParams.has("a")).toBeTruthy();
      expect(searchParams.has("b")).toBeTruthy();
      expect(searchParams.get("a")).toEqual("1");
      expect(searchParams.get("b")).toEqual("2");
    });

    it("should merge both sides, giving priority to right", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { a: 1, b: 1 },
        { b: 2 }
      );
      expect(searchParams.has("a")).toBeTruthy();
      expect(searchParams.has("b")).toBeTruthy();
      expect(searchParams.get("a")).toEqual("1");
      expect(searchParams.get("b")).toEqual("2");
    });

    it("should not include properties listed to exclude", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { a: 1, b: 1 },
        { b: 2 },
        ["a"]
      );
      expect(searchParams.has("a")).toBeFalsy();
      expect(searchParams.get("b")).toEqual("2");
    });

    it("should merge scope, when scope is defined as a string", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { scope: "a b" },
        { scope: "c" }
      );
      expect(searchParams.has("scope")).toBeTruthy();
      expect(searchParams.get("scope")).toEqual("c");
    });

    it("should merge scope, when scope is defined as a map on the left but string on the right", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { audience: "audience", scope: { ["audience"]: "a b" } },
        { audience: "audience", scope: "c" }
      );
      expect(searchParams.has("scope")).toBeTruthy();
      expect(searchParams.get("scope")).toEqual("c");
    });

    it("should merge scope, when scope is defined as a map on the right but string on the left", () => {
      const searchParams = mergeAuthorizationParamsIntoSearchParams(
        { audience: "audience", scope: "c" },
        { audience: "audience", scope: { ["audience"]: "a b" } }
      );
      expect(searchParams.has("scope")).toBeTruthy();
      expect(searchParams.get("scope")).toEqual("a b");
    });
  });
});
