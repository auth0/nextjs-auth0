import { describe, expect, it } from "vitest";

import {
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  OAuth2Error
} from "./index.js";

describe("MFA Errors", () => {
  describe("MfaRequiredError", () => {
    it("should create error with required properties", () => {
      const error = new MfaRequiredError(
        "MFA is required",
        "encrypted-mfa-token"
      );

      expect(error.name).toBe("MfaRequiredError");
      expect(error.code).toBe("mfa_required");
      expect(error.error).toBe("mfa_required");
      expect(error.message).toBe("MFA is required");
      expect(error.error_description).toBe("MFA is required");
      expect(error.mfa_token).toBe("encrypted-mfa-token");
      expect(error.mfa_requirements).toBeUndefined();
      expect(error.cause).toBeUndefined();
    });

    it("should create error with all optional properties", () => {
      const cause = new OAuth2Error({
        code: "mfa_required",
        message: "Multi-factor auth needed"
      });
      const mfaRequirements = {
        challenge: [{ type: "otp" }, { type: "push" }],
        enroll: [{ type: "sms" }]
      };

      const error = new MfaRequiredError(
        "MFA is required",
        "encrypted-token",
        mfaRequirements,
        cause
      );

      expect(error.mfa_requirements).toEqual(mfaRequirements);
      expect(error.cause).toBe(cause);
    });

    it("should be an instance of Error", () => {
      const error = new MfaRequiredError("MFA required", "token");
      expect(error).toBeInstanceOf(Error);
    });

    describe("toJSON", () => {
      it("should serialize to JSON with required fields", () => {
        const error = new MfaRequiredError(
          "MFA is required",
          "encrypted-mfa-token"
        );

        const json = error.toJSON();

        expect(json).toEqual({
          error: "mfa_required",
          error_description: "MFA is required",
          mfa_token: "encrypted-mfa-token"
        });
      });

      it("should include mfa_requirements when present", () => {
        const mfaRequirements = {
          challenge: [{ type: "otp" }]
        };
        const error = new MfaRequiredError(
          "MFA is required",
          "token",
          mfaRequirements
        );

        const json = error.toJSON();

        expect(json).toEqual({
          error: "mfa_required",
          error_description: "MFA is required",
          mfa_token: "token",
          mfa_requirements: mfaRequirements
        });
      });

      it("should not include mfa_requirements when undefined", () => {
        const error = new MfaRequiredError("MFA required", "token", undefined);

        const json = error.toJSON();

        expect(Object.keys(json)).not.toContain("mfa_requirements");
      });

      it("should work with JSON.stringify", () => {
        const error = new MfaRequiredError("MFA required", "token");

        const stringified = JSON.stringify(error);
        const parsed = JSON.parse(stringified);

        expect(parsed.error).toBe("mfa_required");
        expect(parsed.mfa_token).toBe("token");
      });
    });
  });

  describe("MfaTokenExpiredError", () => {
    it("should create error with fixed message", () => {
      const error = new MfaTokenExpiredError();

      expect(error.name).toBe("MfaTokenExpiredError");
      expect(error.code).toBe("mfa_token_expired");
      expect(error.message).toBe(
        "MFA token has expired. Please restart the MFA flow."
      );
    });
  });

  describe("MfaTokenInvalidError", () => {
    it("should create error with fixed message", () => {
      const error = new MfaTokenInvalidError();

      expect(error.name).toBe("MfaTokenInvalidError");
      expect(error.code).toBe("mfa_token_invalid");
      expect(error.message).toBe("MFA token is invalid.");
    });
  });
});
