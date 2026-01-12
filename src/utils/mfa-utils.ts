import { createHmac } from "crypto";

const MFA_TOKEN_HASH_KEY = "mfa-token-hash-key";

import {
  MfaRequirements,
  MfaTokenExpiredError,
  MfaTokenInvalidError
} from "../errors/index.js";
import { decrypt, encrypt } from "../server/cookies.js";
import type { MfaContext, SessionData } from "../types/index.js";

/**
 * Generate SHA-256 hash of raw mfa_token for session key.
 * Truncated to 16 hex characters (64 bits) for reasonable key size.
 *
 * @param rawMfaToken - The raw mfa_token from Auth0
 * @returns 16-character hex string for use as session key
 */
export function hashMfaToken(rawMfaToken: string): string {
  return createHmac("sha256", MFA_TOKEN_HASH_KEY)
    .update(rawMfaToken)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Encrypt mfa_token before exposing to application.
 * Uses same encryption as session cookies (JWE with AES-256-GCM).
 *
 * @param mfaToken - Raw mfa_token from Auth0
 * @param secret - Cookie secret for encryption
 * @param ttlSeconds - TTL in seconds for JWE expiration
 * @returns Encrypted JWE string
 */
export async function encryptMfaToken(
  mfaToken: string,
  secret: string,
  ttlSeconds: number
): Promise<string> {
  const expiration = Math.floor(Date.now() / 1000) + ttlSeconds;
  return await encrypt({ mfa_token: mfaToken }, secret, expiration);
}

/**
 * Decrypt encrypted mfa_token from application.
 *
 * @param encryptedToken - Encrypted JWE from MfaRequiredError
 * @param secret - Cookie secret for decryption
 * @returns Raw mfa_token
 * @throws MfaTokenExpiredError if JWE TTL exceeded
 * @throws MfaTokenInvalidError if token is tampered/malformed
 */
export async function decryptMfaToken(
  encryptedToken: string,
  secret: string
): Promise<string> {
  try {
    const result = await decrypt<{ mfa_token: string }>(encryptedToken, secret);

    // decrypt() returns null for expired tokens (ERR_JWT_EXPIRED)
    if (!result) {
      throw new MfaTokenExpiredError();
    }

    return result.payload.mfa_token;
  } catch (e) {
    if (e instanceof MfaTokenExpiredError) {
      throw e;
    }
    // Any other error means tampered, malformed, or wrong secret
    throw new MfaTokenInvalidError();
  }
}

/**
 * Detect if an OAuth error response indicates MFA is required.
 * Works with oauth4webapi's ResponseBodyError which has `error` property directly.
 *
 * @param error - Error object from oauth4webapi
 * @returns True if error indicates mfa_required
 */
export function isMfaRequiredError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as Record<string, unknown>;
  return err.error === "mfa_required" || err.code === "mfa_required";
}

/**
 * Extract mfa_token and error details from Auth0's mfa_required response.
 * oauth4webapi's ResponseBodyError puts custom fields (mfa_token, mfa_requirements)
 * in the `cause` property, while `error` and `error_description` are directly on the error.
 *
 * @param error - Error object from oauth4webapi containing Auth0 response
 * @returns Object with mfa_token, error_description, and mfa_requirements if present
 */
export function extractMfaErrorDetails(error: unknown): {
  mfa_token: string | undefined;
  error_description: string | undefined;
  mfa_requirements: MfaRequirements | undefined;
} {
  if (!error || typeof error !== "object") {
    return {
      mfa_token: undefined,
      error_description: undefined,
      mfa_requirements: undefined
    };
  }
  const err = error as Record<string, unknown>;

  // oauth4webapi's ResponseBodyError has:
  // - error, error_description: directly on the error object
  // - cause: contains the full response body with mfa_token, mfa_requirements
  const cause = err.cause as Record<string, unknown> | undefined;

  return {
    // mfa_token and mfa_requirements are in the cause (response body)
    mfa_token:
      (cause?.mfa_token as string | undefined) ??
      (err.mfa_token as string | undefined),
    // error_description is directly on the error
    error_description: err.error_description as string | undefined,
    // mfa_requirements is in the cause (response body)
    mfa_requirements:
      (cause?.mfa_requirements as MfaRequirements | undefined) ??
      (err.mfa_requirements as MfaRequirements | undefined)
  };
}

/**
 * Remove expired MFA contexts from session data.
 * Called during session write operations only (not read).
 *
 * @param session - Session data to clean
 * @param ttlMs - MFA context TTL in milliseconds (passed from config)
 * @returns New session object with expired MFA contexts removed
 */
export function cleanupExpiredMfaContexts(
  session: SessionData,
  ttlMs: number
): SessionData {
  if (!session.mfa || Object.keys(session.mfa).length === 0) {
    return session;
  }

  const now = Date.now();
  const cleanedMfa: Record<string, MfaContext> = {};
  let hasExpired = false;

  for (const [hash, context] of Object.entries(session.mfa)) {
    if (now - context.createdAt <= ttlMs) {
      cleanedMfa[hash] = context;
    } else {
      hasExpired = true;
    }
  }

  if (!hasExpired) {
    return session;
  }

  return {
    ...session,
    mfa: Object.keys(cleanedMfa).length > 0 ? cleanedMfa : undefined
  };
}
