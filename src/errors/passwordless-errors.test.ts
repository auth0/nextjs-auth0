import { describe, expect, it } from "vitest";

import {
  PasswordlessStartError,
  PasswordlessVerifyError
} from "./passwordless-errors.js";
import { SdkError } from "./sdk-error.js";

describe("PasswordlessStartError", () => {
  it("is an instance of SdkError and Error", () => {
    const err = new PasswordlessStartError(
      "bad.connection",
      "Connection not found."
    );
    expect(err).toBeInstanceOf(SdkError);
    expect(err).toBeInstanceOf(Error);
  });

  it("sets name to PasswordlessStartError", () => {
    const err = new PasswordlessStartError(
      "bad.connection",
      "Connection not found."
    );
    expect(err.name).toBe("PasswordlessStartError");
  });

  it("sets error and error_description fields", () => {
    const err = new PasswordlessStartError("rate_limit", "Too many requests.");
    expect(err.error).toBe("rate_limit");
    expect(err.error_description).toBe("Too many requests.");
  });

  it("exposes code getter returning passwordless_start_error", () => {
    const err = new PasswordlessStartError(
      "bad.connection",
      "Connection not found."
    );
    expect(err.code).toBe("passwordless_start_error");
  });

  it("serializes to JSON with error and error_description only", () => {
    const err = new PasswordlessStartError("bad.connection", "desc");
    expect(err.toJSON()).toEqual({
      error: "bad.connection",
      error_description: "desc"
    });
  });

  it("stores optional cause when provided", () => {
    const cause = { error: "bad.connection", error_description: "desc" };
    const err = new PasswordlessStartError("bad.connection", "desc", cause);
    expect(err.cause).toBe(cause);
  });

  it("cause is undefined when not provided", () => {
    const err = new PasswordlessStartError("bad.connection", "desc");
    expect(err.cause).toBeUndefined();
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasswordlessStartError("bad.connection", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessStartError);
    }
  });
});

describe("PasswordlessVerifyError", () => {
  it("is an instance of SdkError and Error", () => {
    const err = new PasswordlessVerifyError("invalid_grant", "Wrong code.");
    expect(err).toBeInstanceOf(SdkError);
    expect(err).toBeInstanceOf(Error);
  });

  it("sets name to PasswordlessVerifyError", () => {
    const err = new PasswordlessVerifyError("invalid_grant", "Wrong code.");
    expect(err.name).toBe("PasswordlessVerifyError");
  });

  it("sets error and error_description fields", () => {
    const err = new PasswordlessVerifyError("expired_token", "Token expired.");
    expect(err.error).toBe("expired_token");
    expect(err.error_description).toBe("Token expired.");
  });

  it("exposes code getter returning passwordless_verify_error", () => {
    const err = new PasswordlessVerifyError("invalid_grant", "Wrong code.");
    expect(err.code).toBe("passwordless_verify_error");
  });

  it("serializes to JSON with error and error_description only", () => {
    const err = new PasswordlessVerifyError("invalid_grant", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_grant",
      error_description: "desc"
    });
  });

  it("stores optional cause when provided", () => {
    const cause = { error: "invalid_grant", error_description: "desc" };
    const err = new PasswordlessVerifyError("invalid_grant", "desc", cause);
    expect(err.cause).toBe(cause);
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasswordlessVerifyError("invalid_grant", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessVerifyError);
    }
  });
});
