import { describe, expect, it } from "vitest";

import {
  PasskeyChallengeError,
  PasskeyEnrollmentChallengeError,
  PasskeyEnrollmentVerifyError,
  PasskeyGetTokenError,
  PasskeyRegisterError
} from "./passkey-errors.js";
import { SdkError } from "./sdk-error.js";

describe("PasskeyRegisterError", () => {
  it("is an instance of SdkError and Error", () => {
    const err = new PasskeyRegisterError(
      "invalid_request",
      "Passkeys not enabled."
    );
    expect(err).toBeInstanceOf(SdkError);
    expect(err).toBeInstanceOf(Error);
  });

  it("sets name to PasskeyRegisterError", () => {
    const err = new PasskeyRegisterError(
      "invalid_request",
      "Passkeys not enabled."
    );
    expect(err.name).toBe("PasskeyRegisterError");
  });

  it("sets error and error_description", () => {
    const err = new PasskeyRegisterError("forbidden", "Not allowed.");
    expect(err.error).toBe("forbidden");
    expect(err.error_description).toBe("Not allowed.");
  });

  it("exposes code getter returning passkey_register_error", () => {
    const err = new PasskeyRegisterError("invalid_request", "desc");
    expect(err.code).toBe("passkey_register_error");
  });

  it("serializes to JSON correctly", () => {
    const err = new PasskeyRegisterError("invalid_request", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_request",
      error_description: "desc"
    });
  });

  it("stores optional cause", () => {
    const cause = { error: "invalid_request", error_description: "desc" };
    const err = new PasskeyRegisterError("invalid_request", "desc", cause);
    expect(err.cause).toBe(cause);
  });

  it("cause is undefined when not provided", () => {
    const err = new PasskeyRegisterError("invalid_request", "desc");
    expect(err.cause).toBeUndefined();
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasskeyRegisterError("invalid_request", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasskeyRegisterError);
    }
  });
});

describe("PasskeyChallengeError", () => {
  it("sets name to PasskeyChallengeError", () => {
    const err = new PasskeyChallengeError(
      "not_found",
      "No passkey registered."
    );
    expect(err.name).toBe("PasskeyChallengeError");
  });

  it("exposes code getter returning passkey_challenge_error", () => {
    const err = new PasskeyChallengeError("not_found", "desc");
    expect(err.code).toBe("passkey_challenge_error");
  });

  it("serializes to JSON correctly", () => {
    const err = new PasskeyChallengeError("not_found", "desc");
    expect(err.toJSON()).toEqual({
      error: "not_found",
      error_description: "desc"
    });
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasskeyChallengeError("not_found", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasskeyChallengeError);
    }
  });
});

describe("PasskeyGetTokenError", () => {
  it("sets name to PasskeyGetTokenError", () => {
    const err = new PasskeyGetTokenError(
      "invalid_grant",
      "Invalid auth_session."
    );
    expect(err.name).toBe("PasskeyGetTokenError");
  });

  it("exposes code getter returning passkey_get_token_error", () => {
    const err = new PasskeyGetTokenError("invalid_grant", "desc");
    expect(err.code).toBe("passkey_get_token_error");
  });

  it("serializes to JSON correctly", () => {
    const err = new PasskeyGetTokenError("invalid_grant", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_grant",
      error_description: "desc"
    });
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasskeyGetTokenError("invalid_grant", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasskeyGetTokenError);
    }
  });
});

describe("PasskeyEnrollmentChallengeError", () => {
  it("sets name to PasskeyEnrollmentChallengeError", () => {
    const err = new PasskeyEnrollmentChallengeError(
      "unauthorized",
      "Not authenticated."
    );
    expect(err.name).toBe("PasskeyEnrollmentChallengeError");
  });

  it("exposes code getter returning passkey_enrollment_challenge_error", () => {
    const err = new PasskeyEnrollmentChallengeError("unauthorized", "desc");
    expect(err.code).toBe("passkey_enrollment_challenge_error");
  });

  it("serializes to JSON correctly", () => {
    const err = new PasskeyEnrollmentChallengeError("unauthorized", "desc");
    expect(err.toJSON()).toEqual({
      error: "unauthorized",
      error_description: "desc"
    });
  });

  it("stores optional cause object", () => {
    const cause = { type: "problem", detail: "insufficient scope" };
    const err = new PasskeyEnrollmentChallengeError(
      "unauthorized",
      "desc",
      cause
    );
    expect(err.cause).toBe(cause);
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasskeyEnrollmentChallengeError("unauthorized", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasskeyEnrollmentChallengeError);
    }
  });
});

describe("PasskeyEnrollmentVerifyError", () => {
  it("sets name to PasskeyEnrollmentVerifyError", () => {
    const err = new PasskeyEnrollmentVerifyError(
      "invalid_grant",
      "Credential rejected."
    );
    expect(err.name).toBe("PasskeyEnrollmentVerifyError");
  });

  it("exposes code getter returning passkey_enrollment_verify_error", () => {
    const err = new PasskeyEnrollmentVerifyError("invalid_grant", "desc");
    expect(err.code).toBe("passkey_enrollment_verify_error");
  });

  it("serializes to JSON correctly", () => {
    const err = new PasskeyEnrollmentVerifyError("invalid_grant", "desc");
    expect(err.toJSON()).toEqual({
      error: "invalid_grant",
      error_description: "desc"
    });
  });

  it("stores optional cause object", () => {
    const cause = { detail: "duplicate passkey" };
    const err = new PasskeyEnrollmentVerifyError(
      "invalid_grant",
      "desc",
      cause
    );
    expect(err.cause).toBe(cause);
  });

  it("is catchable by instanceof after prototype chain fix", () => {
    try {
      throw new PasskeyEnrollmentVerifyError("invalid_grant", "desc");
    } catch (e) {
      expect(e).toBeInstanceOf(PasskeyEnrollmentVerifyError);
    }
  });
});
