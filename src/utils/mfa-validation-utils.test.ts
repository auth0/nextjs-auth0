import { NextRequest } from "next/server.js";
import { describe, expect, it } from "vitest";

import { InvalidRequestError } from "../errors/index.js";
import {
  extractBearerToken,
  extractMfaToken,
  extractPathParam,
  parseJsonBody,
  validateArrayFieldAndThrow,
  validateStringFieldAndThrow,
  validateVerificationCredentialAndThrow
} from "./mfa-validation-utils.js";

// ─── extractBearerToken ───────────────────────────────────────────────────────

describe("extractBearerToken", () => {
  it("extracts the token from a valid Bearer header", () => {
    const req = new NextRequest("https://example.com/api", {
      headers: { Authorization: "Bearer my-token-123" }
    });
    expect(extractBearerToken(req)).toBe("my-token-123");
  });

  it("throws InvalidRequestError when Authorization header is missing", () => {
    const req = new NextRequest("https://example.com/api");
    expect(() => extractBearerToken(req)).toThrow(InvalidRequestError);
  });

  it("throws InvalidRequestError when Authorization header does not start with Bearer ", () => {
    const req = new NextRequest("https://example.com/api", {
      headers: { Authorization: "Basic dXNlcjpwYXNz" }
    });
    expect(() => extractBearerToken(req)).toThrow(InvalidRequestError);
  });

  it("throws InvalidRequestError for empty Authorization header", () => {
    const req = new NextRequest("https://example.com/api", {
      headers: { Authorization: "" }
    });
    expect(() => extractBearerToken(req)).toThrow(InvalidRequestError);
  });
});

// ─── extractMfaToken ─────────────────────────────────────────────────────────

describe("extractMfaToken", () => {
  it("delegates to extractBearerToken and returns the token", () => {
    const req = new NextRequest("https://example.com/api", {
      headers: { Authorization: "Bearer mfa-token-xyz" }
    });
    expect(extractMfaToken(req)).toBe("mfa-token-xyz");
  });

  it("throws when Authorization header is missing", () => {
    const req = new NextRequest("https://example.com/api");
    expect(() => extractMfaToken(req)).toThrow(InvalidRequestError);
  });
});

// ─── validateStringFieldAndThrow ─────────────────────────────────────────────

describe("validateStringFieldAndThrow", () => {
  it("returns the value when it is a non-empty string", () => {
    expect(validateStringFieldAndThrow("hello", "field")).toBe("hello");
  });

  it("throws when value is null", () => {
    expect(() => validateStringFieldAndThrow(null, "myField")).toThrow(
      InvalidRequestError
    );
    expect(() => validateStringFieldAndThrow(null, "myField")).toThrow(
      "Missing or invalid myField"
    );
  });

  it("throws when value is undefined", () => {
    expect(() => validateStringFieldAndThrow(undefined, "myField")).toThrow(
      InvalidRequestError
    );
  });

  it("throws when value is an empty string", () => {
    expect(() => validateStringFieldAndThrow("", "myField")).toThrow(
      InvalidRequestError
    );
  });

  it("throws when value is a number", () => {
    expect(() => validateStringFieldAndThrow(42, "myField")).toThrow(
      InvalidRequestError
    );
  });
});

// ─── validateArrayFieldAndThrow ──────────────────────────────────────────────

describe("validateArrayFieldAndThrow", () => {
  it("returns the array when it is non-empty", () => {
    expect(validateArrayFieldAndThrow(["a", "b"], "field")).toEqual(["a", "b"]);
  });

  it("throws when value is null", () => {
    expect(() => validateArrayFieldAndThrow(null, "items")).toThrow(
      InvalidRequestError
    );
    expect(() => validateArrayFieldAndThrow(null, "items")).toThrow(
      "Missing or invalid items"
    );
  });

  it("throws when value is undefined", () => {
    expect(() => validateArrayFieldAndThrow(undefined, "items")).toThrow(
      InvalidRequestError
    );
  });

  it("throws when value is not an array", () => {
    expect(() => validateArrayFieldAndThrow("not-an-array", "items")).toThrow(
      InvalidRequestError
    );
  });

  it("throws when array is empty", () => {
    expect(() => validateArrayFieldAndThrow([], "items")).toThrow(
      InvalidRequestError
    );
  });
});

// ─── validateVerificationCredentialAndThrow ───────────────────────────────────

describe("validateVerificationCredentialAndThrow", () => {
  it("returns the body when otp is present", () => {
    const body = { otp: "123456" };
    expect(validateVerificationCredentialAndThrow(body)).toBe(body);
  });

  it("returns the body when oob_code and binding_code are present", () => {
    const body = { oob_code: "abc", binding_code: "def" };
    expect(validateVerificationCredentialAndThrow(body)).toBe(body);
  });

  it("returns the body when recovery_code is present", () => {
    const body = { recovery_code: "backup-code" };
    expect(validateVerificationCredentialAndThrow(body)).toBe(body);
  });

  it("throws when all credentials are missing", () => {
    expect(() => validateVerificationCredentialAndThrow({})).toThrow(
      InvalidRequestError
    );
  });

  it("throws when otp is an empty string", () => {
    expect(() => validateVerificationCredentialAndThrow({ otp: "" })).toThrow(
      InvalidRequestError
    );
  });

  it("throws when oob_code is present but binding_code is missing", () => {
    expect(() =>
      validateVerificationCredentialAndThrow({ oob_code: "abc" })
    ).toThrow(InvalidRequestError);
  });

  it("throws when binding_code is present but oob_code is missing", () => {
    expect(() =>
      validateVerificationCredentialAndThrow({ binding_code: "def" })
    ).toThrow(InvalidRequestError);
  });

  it("throws when recovery_code is an empty string", () => {
    expect(() =>
      validateVerificationCredentialAndThrow({ recovery_code: "" })
    ).toThrow(InvalidRequestError);
  });
});

// ─── extractPathParam ─────────────────────────────────────────────────────────

describe("extractPathParam", () => {
  it("extracts the last segment from a URL path", () => {
    expect(
      extractPathParam("/auth/mfa/authenticators/auth_123", "authenticatorId")
    ).toBe("auth_123");
  });

  it("throws when pathname is just a slash", () => {
    expect(() => extractPathParam("/", "id")).toThrow(InvalidRequestError);
    expect(() => extractPathParam("/", "id")).toThrow("Missing id in URL");
  });

  it("throws when pathname ends with a slash (empty final segment)", () => {
    expect(() => extractPathParam("/auth/mfa/authenticators/", "id")).toThrow(
      InvalidRequestError
    );
  });

  it("returns the only segment for a single-segment path", () => {
    expect(extractPathParam("/auth_123", "id")).toBe("auth_123");
  });
});

// ─── parseJsonBody ────────────────────────────────────────────────────────────

describe("parseJsonBody", () => {
  it("parses valid JSON body from request", async () => {
    const req = new NextRequest("https://example.com/api", {
      method: "POST",
      body: JSON.stringify({ otp: "123456" }),
      headers: { "Content-Type": "application/json" }
    });
    const result = await parseJsonBody(req);
    expect(result).toEqual({ otp: "123456" });
  });

  it("throws InvalidRequestError for malformed JSON", async () => {
    const req = new NextRequest("https://example.com/api", {
      method: "POST",
      body: "not-json",
      headers: { "Content-Type": "application/json" }
    });
    await expect(parseJsonBody(req)).rejects.toThrow(InvalidRequestError);
    await expect(parseJsonBody(req)).rejects.toThrow("Invalid JSON");
  });
});
