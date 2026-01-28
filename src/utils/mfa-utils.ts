import { NextResponse } from "next/server.js";

import {
  InvalidRequestError,
  MfaChallengeError,
  MfaGetAuthenticatorsError,
  MfaNoAvailableFactorsError,
  MfaRequiredError,
  MfaRequirements,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  MfaVerifyError,
  OAuth2Error,
  SdkError
} from "../errors/index.js";
import { decrypt, encrypt } from "../server/cookies.js";
import type { MfaContext } from "../types/index.js";

/**
 * Encrypt mfa_token with full context before exposing to application.
 * Uses same encryption as session cookies (JWE with AES-256-GCM).
 * The encrypted token is self-contained with audience, scope, and requirements.
 *
 * @param mfaToken - Raw mfa_token from Auth0
 * @param audience - The API audience the token is for
 * @param scope - The requested scope
 * @param mfaRequirements - MFA requirements from Auth0
 * @param secret - Cookie secret for encryption
 * @param ttlSeconds - TTL in seconds for JWE expiration
 * @returns Encrypted JWE string containing full MFA context
 */
export async function encryptMfaToken(
  mfaToken: string,
  audience: string,
  scope: string,
  mfaRequirements: MfaRequirements | undefined,
  secret: string,
  ttlSeconds: number
): Promise<string> {
  const context: MfaContext = {
    mfaToken,
    audience,
    scope,
    mfaRequirements,
    createdAt: Date.now()
  };
  return await encrypt(
    context as any,
    secret,
    Math.floor(Date.now() / 1000) + ttlSeconds
  );
}

/**
 * Decrypt encrypted mfa_token from application to extract full context.
 *
 * @param encryptedToken - Encrypted JWE from MfaRequiredError
 * @param secret - Cookie secret for decryption
 * @returns MfaContext with mfaToken, audience, scope, and requirements
 * @throws MfaTokenExpiredError if JWE TTL exceeded
 * @throws MfaTokenInvalidError if token is tampered/malformed
 */
export async function decryptMfaToken(
  encryptedToken: string,
  secret: string
): Promise<MfaContext> {
  try {
    const result = await decrypt<MfaContext>(
      encryptedToken,
      secret,
      undefined,
      true
    );

    return result!.payload;
  } catch (e: any) {
    if (e.code === "ERR_JWT_EXPIRED") {
      throw new MfaTokenExpiredError();
    }
    // ERR_JWE_DECRYPTION_FAILED or any other error means tampered, malformed, or wrong secret
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
 * Get HTTP status code for MFA error.
 *
 * Centralized mapping: 401 (auth), 400 (validation), 500 (unexpected)
 *
 * @param error - Error instance
 * @returns HTTP status code
 */
export function getMfaErrorStatusCode(error: Error): number {
  if (
    error instanceof MfaTokenExpiredError ||
    error instanceof MfaTokenInvalidError
  ) {
    return 401;
  }

  if (
    error instanceof InvalidRequestError ||
    error instanceof MfaNoAvailableFactorsError ||
    error instanceof MfaGetAuthenticatorsError ||
    error instanceof MfaChallengeError ||
    error instanceof MfaVerifyError ||
    error instanceof MfaRequiredError
  ) {
    return 400;
  }

  return 500;
}

/**
 * Handle MFA errors and format response.
 *
 * Wraps non-SDK errors for consistent shape, uses error.toJSON() for serialization.
 *
 * @param e - Error thrown by business logic
 * @returns NextResponse with error details
 */
export function handleMfaError(e: unknown): NextResponse {
  // Wrap non-SDK errors in OAuth2Error for consistent shape
  if (!(e instanceof SdkError)) {
    e = new OAuth2Error({
      code: "server_error",
      message: e instanceof Error ? e.message : "Internal server error"
    });
  }

  const error = e as SdkError;
  const status = getMfaErrorStatusCode(error);

  // MfaRequiredError has toJSON() with mfa_token + mfa_requirements
  // MfaError subclasses have toJSON() with error + error_description
  // Other SdkErrors fallback to generic shape
  const body = (error as any).toJSON?.() ?? {
    error: error.code || "server_error",
    error_description: error.message || "Internal server error"
  };

  return NextResponse.json(body, { status });
}
