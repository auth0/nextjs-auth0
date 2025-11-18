import { describe, expect, it } from "vitest";

import { isRequest } from "./request.js";

describe("isRequest", () => {
  it("returns true for a Fetch Request instance", () => {
    const req = new Request("https://example.com/api");
    expect(isRequest(req)).toBe(true);
  });

  it("returns true for an object with Headers instance", () => {
    const req = { headers: new Headers({ "x-test": "1" }) };
    expect(isRequest(req as any)).toBe(true);
  });

  it("returns true for an object exposing bodyUsed", () => {
    const req = { bodyUsed: false };
    expect(isRequest(req as any)).toBe(true);
  });

  it("returns false for plain objects without request traits", () => {
    const req = { headers: { "x-test": "1" } };
    expect(isRequest(req as any)).toBe(false);
  });
});
