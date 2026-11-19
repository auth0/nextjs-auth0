import { describe, expect, it } from "vitest";

import { isUnixSeconds } from "./session-helpers.js";

describe("isUnixSeconds", () => {
  it("accepts a positive Unix time in seconds", () => {
    expect(isUnixSeconds(1)).toBe(true);
    expect(isUnixSeconds(1_790_900_000)).toBe(true);
    expect(isUnixSeconds(9_999_999_999)).toBe(true);
  });

  it.each([
    ["zero", 0],
    ["a negative", -1],
    ["a millisecond timestamp", 1_790_900_000_000],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a numeric string", "1790900000"],
    ["null", null],
    ["undefined", undefined],
    ["an object", {}]
  ])("rejects %s", (_case, value) => {
    expect(isUnixSeconds(value)).toBe(false);
  });
});
