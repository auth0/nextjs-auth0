import { describe, expect, it } from "vitest";

import { MfaTokenExpiredError, MfaTokenInvalidError } from "../errors/index.js";
import { generateSecret } from "../test/utils.js";
import type { MfaContext, SessionData } from "../types/index.js";
import {
  cleanupExpiredMfaContexts,
  decryptMfaToken,
  encryptMfaToken,
  extractMfaErrorDetails,
  hashMfaToken,
  isMfaRequiredError
} from "./mfa-utils.js";

describe("mfa-utils", () => {
  describe("hashMfaToken", () => {
    it("should return a 16-character hex string", () => {
      const hash = hashMfaToken("test-mfa-token");
      expect(hash).toHaveLength(16);
      expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
    });

    it("should return consistent hash for same input", () => {
      const token = "my-mfa-token-123";
      const hash1 = hashMfaToken(token);
      const hash2 = hashMfaToken(token);
      expect(hash1).toBe(hash2);
    });

    it("should return different hashes for different inputs", () => {
      const hash1 = hashMfaToken("token-a");
      const hash2 = hashMfaToken("token-b");
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("encryptMfaToken/decryptMfaToken", async () => {
    const secret = await generateSecret(32);
    const incorrectSecret = await generateSecret(32);

    it("should encrypt and decrypt token successfully", async () => {
      const mfaToken = "raw-mfa-token-from-auth0";
      const ttlSeconds = 300;

      const encrypted = await encryptMfaToken(mfaToken, secret, ttlSeconds);
      const decrypted = await decryptMfaToken(encrypted, secret);

      expect(decrypted).toBe(mfaToken);
    });

    it("should throw MfaTokenInvalidError when decrypting with wrong secret", async () => {
      const mfaToken = "raw-mfa-token";
      const encrypted = await encryptMfaToken(mfaToken, secret, 300);

      await expect(decryptMfaToken(encrypted, incorrectSecret)).rejects.toThrow(
        MfaTokenInvalidError
      );
    });

    it("should throw MfaTokenExpiredError when token is expired", async () => {
      const mfaToken = "raw-mfa-token";
      // Use negative TTL to create an already-expired token
      const ttlSeconds = -60;

      const encrypted = await encryptMfaToken(mfaToken, secret, ttlSeconds);

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

  describe("cleanupExpiredMfaContexts", () => {
    const createMockSession = (
      mfa?: Record<string, MfaContext>
    ): SessionData => ({
      user: { sub: "user-123" },
      tokenSet: {
        accessToken: "access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      },
      internal: {
        sid: "session-id",
        createdAt: Math.floor(Date.now() / 1000)
      },
      mfa
    });

    it("should return session unchanged when no mfa property", () => {
      const session = createMockSession();
      delete session.mfa;

      const result = cleanupExpiredMfaContexts(session, 300_000);

      expect(result).toBe(session);
      expect(result.mfa).toBeUndefined();
    });

    it("should return session unchanged when mfa is empty", () => {
      const session = createMockSession({});

      const result = cleanupExpiredMfaContexts(session, 300_000);

      expect(result).toBe(session);
    });

    it("should keep non-expired MFA contexts", () => {
      const now = Date.now();
      const session = createMockSession({
        hash1: {
          audience: "https://api.example.com",
          scope: "openid profile",
          createdAt: now - 60_000 // 1 minute ago
        }
      });

      const result = cleanupExpiredMfaContexts(session, 300_000); // 5 minute TTL

      expect(result).toBe(session); // No change needed
      expect(result.mfa).toBeDefined();
      expect(result.mfa!["hash1"]).toBeDefined();
    });

    it("should remove expired MFA contexts", () => {
      const now = Date.now();
      const session = createMockSession({
        hash1: {
          audience: "https://api.example.com",
          scope: "openid profile",
          createdAt: now - 400_000 // 6.67 minutes ago (expired)
        }
      });

      const result = cleanupExpiredMfaContexts(session, 300_000); // 5 minute TTL

      expect(result).not.toBe(session); // New object returned
      expect(result.mfa).toBeUndefined(); // All contexts expired
    });

    it("should keep valid contexts and remove expired ones", () => {
      const now = Date.now();
      const session = createMockSession({
        validHash: {
          audience: "https://api1.example.com",
          scope: "openid",
          createdAt: now - 60_000 // 1 minute ago (valid)
        },
        expiredHash: {
          audience: "https://api2.example.com",
          scope: "openid profile",
          createdAt: now - 400_000 // 6.67 minutes ago (expired)
        }
      });

      const result = cleanupExpiredMfaContexts(session, 300_000); // 5 minute TTL

      expect(result).not.toBe(session);
      expect(result.mfa).toBeDefined();
      expect(result.mfa!["validHash"]).toBeDefined();
      expect(result.mfa!["expiredHash"]).toBeUndefined();
    });

    it("should set mfa to undefined when all contexts expire", () => {
      const now = Date.now();
      const session = createMockSession({
        hash1: {
          audience: "https://api1.example.com",
          scope: "openid",
          createdAt: now - 400_000
        },
        hash2: {
          audience: "https://api2.example.com",
          scope: "openid",
          createdAt: now - 500_000
        }
      });

      const result = cleanupExpiredMfaContexts(session, 300_000);

      expect(result.mfa).toBeUndefined();
    });

    it("should preserve other session properties", () => {
      const now = Date.now();
      const session = createMockSession({
        expiredHash: {
          audience: "https://api.example.com",
          scope: "openid",
          createdAt: now - 400_000
        }
      });
      // Add custom property
      (session as any).customProp = "custom-value";

      const result = cleanupExpiredMfaContexts(session, 300_000);

      expect(result.user).toEqual(session.user);
      expect(result.tokenSet).toEqual(session.tokenSet);
      expect(result.internal).toEqual(session.internal);
      expect((result as any).customProp).toBe("custom-value");
    });

    it("should handle TTL boundary exactly at expiration", () => {
      const now = Date.now();
      const session = createMockSession({
        exactlyExpired: {
          audience: "https://api.example.com",
          scope: "openid",
          createdAt: now - 300_000 // Exactly at TTL boundary
        }
      });

      const result = cleanupExpiredMfaContexts(session, 300_000);

      // Context at exactly TTL should still be valid (<=)
      expect(result).toBe(session);
      expect(result.mfa!["exactlyExpired"]).toBeDefined();
    });
  });
});
