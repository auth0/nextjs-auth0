import { describe, expect, it } from "vitest";

import { MfaTokenExpiredError, MfaTokenInvalidError } from "../errors/index.js";
import { generateSecret } from "../test/utils.js";
import {
  decryptMfaToken,
  encryptMfaToken,
  extractMfaErrorDetails,
  isMfaRequiredError
} from "./mfa-utils.js";

describe("mfa-utils", () => {
  describe("encryptMfaToken/decryptMfaToken", async () => {
    const secret = await generateSecret(32);
    const incorrectSecret = await generateSecret(32);

    it("should encrypt and decrypt token successfully", async () => {
      const mfaToken = "raw-mfa-token-from-auth0";
      const audience = "https://api.example.com";
      const scope = "openid profile";
      const requirements = { challenge: [{ type: "totp" }] };
      const ttlSeconds = 300;

      const encrypted = await encryptMfaToken(
        mfaToken,
        audience,
        scope,
        requirements,
        secret,
        ttlSeconds
      );
      const decrypted = await decryptMfaToken(encrypted, secret);

      expect(decrypted.mfaToken).toBe(mfaToken);
      expect(decrypted.audience).toBe(audience);
      expect(decrypted.scope).toBe(scope);
      expect(decrypted.mfaRequirements).toEqual(requirements);
    });

    it("should throw MfaTokenInvalidError when decrypting with wrong secret", async () => {
      const mfaToken = "raw-mfa-token";
      const encrypted = await encryptMfaToken(
        mfaToken,
        "https://api.example.com",
        "openid",
        { challenge: [{ type: "totp" }] },
        secret,
        300
      );

      await expect(decryptMfaToken(encrypted, incorrectSecret)).rejects.toThrow(
        MfaTokenInvalidError
      );
    });

    it("should throw MfaTokenExpiredError when token is expired", async () => {
      const mfaToken = "raw-mfa-token";
      // Use negative TTL to create an already-expired token
      const ttlSeconds = -60;

      const encrypted = await encryptMfaToken(
        mfaToken,
        "https://api.example.com",
        "openid",
        { challenge: [{ type: "totp" }] },
        secret,
        ttlSeconds
      );

      await expect(decryptMfaToken(encrypted, secret)).rejects.toThrow(
        MfaTokenExpiredError
      );
    });

    it("should throw MfaTokenInvalidError for malformed token", async () => {
      const malformedToken = "not-a-valid-jwe";

      await expect(decryptMfaToken(malformedToken, secret)).rejects.toThrow(
        MfaTokenInvalidError
      );
    });
  });

  describe("isMfaRequiredError", () => {
    it("should return true for error with error='mfa_required'", () => {
      const error = { error: "mfa_required", error_description: "MFA needed" };
      expect(isMfaRequiredError(error)).toBe(true);
    });

    it("should return true for error with code='mfa_required'", () => {
      const error = { code: "mfa_required", message: "MFA needed" };
      expect(isMfaRequiredError(error)).toBe(true);
    });

    it("should return false for other error types", () => {
      const error = { error: "invalid_grant", error_description: "Bad token" };
      expect(isMfaRequiredError(error)).toBe(false);
    });

    it("should return false for null/undefined", () => {
      expect(isMfaRequiredError(null)).toBe(false);
      expect(isMfaRequiredError(undefined)).toBe(false);
    });

    it("should return false for non-object types", () => {
      expect(isMfaRequiredError("mfa_required")).toBe(false);
      expect(isMfaRequiredError(123)).toBe(false);
    });
  });

  describe("extractMfaErrorDetails", () => {
    it("should extract MFA details from oauth4webapi ResponseBodyError structure", () => {
      // oauth4webapi puts mfa_token and mfa_requirements in cause (response body)
      // while error_description is directly on the error
      const error = {
        error: "mfa_required",
        error_description: "Multi-factor authentication required",
        cause: {
          error: "mfa_required",
          error_description: "Multi-factor authentication required",
          mfa_token: "raw-mfa-token",
          mfa_requirements: {
            challenge: [{ type: "otp" }]
          }
        }
      };

      const details = extractMfaErrorDetails(error);

      expect(details.mfa_token).toBe("raw-mfa-token");
      expect(details.error_description).toBe(
        "Multi-factor authentication required"
      );
      expect(details.mfa_requirements).toEqual({
        challenge: [{ type: "otp" }]
      });
    });

    it("should fallback to flat structure for backwards compatibility", () => {
      // Support direct properties for simple test cases
      const error = {
        error: "mfa_required",
        error_description: "Multi-factor authentication required",
        mfa_token: "raw-mfa-token",
        mfa_requirements: {
          challenge: [{ type: "otp" }]
        }
      };

      const details = extractMfaErrorDetails(error);

      expect(details.mfa_token).toBe("raw-mfa-token");
      expect(details.error_description).toBe(
        "Multi-factor authentication required"
      );
      expect(details.mfa_requirements).toEqual({
        challenge: [{ type: "otp" }]
      });
    });

    it("should return undefined values for missing properties", () => {
      const error = { error: "mfa_required" };

      const details = extractMfaErrorDetails(error);

      expect(details.mfa_token).toBeUndefined();
      expect(details.error_description).toBeUndefined();
      expect(details.mfa_requirements).toBeUndefined();
    });

    it("should return undefined values for null/undefined input", () => {
      expect(extractMfaErrorDetails(null)).toEqual({
        mfa_token: undefined,
        error_description: undefined,
        mfa_requirements: undefined
      });
      expect(extractMfaErrorDetails(undefined)).toEqual({
        mfa_token: undefined,
        error_description: undefined,
        mfa_requirements: undefined
      });
    });
  });
});
