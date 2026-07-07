import { describe, expect, it } from "vitest";

import {
  PasswordlessDbChallengeError,
  PasswordlessDbGetTokenError
} from "./passwordless-db-errors.js";
import { SdkError } from "./sdk-error.js";

describe("PasswordlessDbChallengeError", () => {
  it("is an instance of SdkError and Error", () => {
    const err = new PasswordlessDbChallengeError(
      "invalid_connection",
      "Not a DB connection."
    );
    expect(err).toBeInstanceOf(SdkError);
    expect(err).toBeInstanceOf(Error);
  });

  it("sets name to PasswordlessDbChallengeError", () => {
    const err = new PasswordlessDbChallengeError(
      "invalid_connection",
      "Not a DB connection."
    );
    expect(err.name).toBe("PasswordlessDbChallengeError");
  });

  it("sets error and error_description fields", () => {
    const err = new PasswordlessDbChallengeError(
      "invalid_request",
      "Missing email."
    );
    expect(err.error).toBe("invalid_request");
    expect(err.error_description).toBe("Missing email.");
  });

  it("exposes code getter returning passwordless_challenge_error", () => {
    const err = new PasswordlessDbChallengeError("invalid_connection", "desc");
    expect(err.code).toBe("passwordless_challenge_error");
  });

  it("serializes to JSON with error and error_description only", () => {
    const err = new PasswordlessDbChallengeError("invalid_connection", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_connection",
      error_description: "desc"
    });
  });

  it("stores optional cause when provided", () => {
    const cause = { error: "invalid_connection", error_description: "desc" };
    const err = new PasswordlessDbChallengeError(
      "invalid_connection",
      "desc",
      cause
    );
    expect(err.cause).toBe(cause);
  });

  it("cause is undefined when not provided", () => {
    const err = new PasswordlessDbChallengeError("invalid_connection", "desc");
    expect(err.cause).toBeUndefined();
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasswordlessDbChallengeError("invalid_connection", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessDbChallengeError);
    }
  });
});

describe("PasswordlessDbGetTokenError", () => {
  it("is an instance of SdkError and Error", () => {
    const err = new PasswordlessDbGetTokenError(
      "invalid_request",
      "Invalid OTP."
    );
    expect(err).toBeInstanceOf(SdkError);
    expect(err).toBeInstanceOf(Error);
  });

  it("sets name to PasswordlessDbGetTokenError", () => {
    const err = new PasswordlessDbGetTokenError(
      "invalid_request",
      "Invalid OTP."
    );
    expect(err.name).toBe("PasswordlessDbGetTokenError");
  });

  it("sets error and error_description fields", () => {
    const err = new PasswordlessDbGetTokenError(
      "discovery_error",
      "Discovery failed."
    );
    expect(err.error).toBe("discovery_error");
    expect(err.error_description).toBe("Discovery failed.");
  });

  it("exposes code getter returning passwordless_login_error", () => {
    const err = new PasswordlessDbGetTokenError("invalid_request", "desc");
    expect(err.code).toBe("passwordless_login_error");
  });

  it("serializes to JSON with error and error_description only", () => {
    const err = new PasswordlessDbGetTokenError("invalid_request", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_request",
      error_description: "desc"
    });
  });

  it("stores optional cause when provided", () => {
    const cause = { error: "invalid_request", error_description: "desc" };
    const err = new PasswordlessDbGetTokenError(
      "invalid_request",
      "desc",
      cause
    );
    expect(err.cause).toBe(cause);
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasswordlessDbGetTokenError("invalid_request", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasswordlessDbGetTokenError);
    }
  });
});
