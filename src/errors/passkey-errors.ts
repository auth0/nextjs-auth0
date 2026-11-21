import type { PasskeyVerificationIdentifier } from "../types/passkey.js";
import { SdkError } from "./sdk-error.js";

/**
 * Shape of an error response from the Auth0 Passkey API.
 */
export interface PasskeyApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for all passkey-related errors.
 * Provides standardized JSON serialization matching Auth0 API format.
 */
abstract class PasskeyError extends SdkError {
  public abstract readonly error: string;
  public abstract readonly error_description: string;

  toJSON(): { error: string; error_description: string } {
    return {
      error: this.error,
      error_description: this.error_description
    };
  }

  public abstract get code(): string;
}

/**
 * Thrown when requesting a passkey signup challenge (POST /passkey/register) fails.
 *
 * Common causes:
 * - Passkeys not enabled for the application
 * - Invalid client configuration
 */
export class PasskeyRegisterError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_register_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyRegisterError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyRegisterError.prototype);
  }
}

/**
 * Thrown when requesting a passkey login challenge (POST /passkey/challenge) fails.
 *
 * Common causes:
 * - Passkeys not enabled for the application
 * - No passkey registered for the user
 */
export class PasskeyChallengeError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyChallengeError.prototype);
  }
}

/**
 * Passkey token exchange error response.
 *
 * In addition to the common fields, a wrong verification code response carries
 * `verification_required` and `auth_session`.
 */
export interface PasskeyGetTokenApiErrorResponse extends PasskeyApiErrorResponse {
  /**
   * Identifiers that still require a valid OTP code. Present on retryable
   * `invalid_grant` (wrong code) responses. Absent on terminal failures.
   */
  verification_required?: PasskeyVerificationIdentifier[];
  /**
   * The auth session token. Present when the session is still alive and the
   * caller may retry the token exchange with corrected OTP codes. Absent when
   * the session is terminal (exhausted, expired, or unknown).
   */
  auth_session?: string;
}

/**
 * Thrown when passkey token exchange (POST /oauth/token with WebAuthn grant) fails.
 *
 * Common causes:
 * - Invalid or expired auth_session
 * - Credential assertion rejected by Auth0
 * - Passkey not recognized
 * - Wrong identifier verification code (check `isRetryable`)
 *
 * When identifier verification is required, `isRetryable` indicates whether the
 * user entered a wrong OTP code. A retryable error means the caller should
 * re-collect OTP codes for the identifiers in `verificationRequired` and retry
 * with the same credential and `authSession`. A non-retryable error is any
 * other error, so check the error before starting a new flow. A rate
 * limit or server error can succeed later.
 */
export class PasskeyGetTokenError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyGetTokenApiErrorResponse;
  /**
   * `true` when Auth0 returned `invalid_grant` with an `auth_session`, meaning
   * the session is still alive and the user can retry with corrected OTP codes.
   * `false` for every other error, so check the error before starting a new flow.
   *
   * Branch on this field — never on HTTP status code or `error_description` text,
   * which are intentionally identical on retryable and terminal `invalid_grant` paths.
   */
  public readonly isRetryable: boolean;
  /**
   * Identifiers that still require a valid OTP code. Only present when `isRetryable`
   * is `true` and the failure was due to a wrong OTP code.
   */
  public readonly verificationRequired?: PasskeyVerificationIdentifier[];
  /**
   * The auth session token to use when retrying. Only present when `isRetryable`
   * is `true`. Never included in the message or `toJSON()`.
   */
  public readonly authSession?: string;

  public get code(): string {
    return "passkey_get_token_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyGetTokenApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyGetTokenError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    // A session is retryable only when Auth0 returns invalid_grant with an
    // auth_session, meaning the session is still alive and the user can retry
    // with corrected OTP codes.
    this.isRetryable = error === "invalid_grant" && cause?.auth_session != null;
    this.verificationRequired = cause?.verification_required;
    this.authSession = cause?.auth_session;
    Object.setPrototypeOf(this, PasskeyGetTokenError.prototype);
  }
}

/**
 * Thrown when requesting a passkey enrollment challenge fails.
 * The MyAccount API returns errors in RFC 7807 problem detail format.
 *
 * Common causes:
 * - User not authenticated
 * - Insufficient scope (requires create:me:authentication_methods)
 * - Passkeys not enabled for the tenant
 */
export class PasskeyEnrollmentChallengeError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: Record<string, unknown>;

  public get code(): string {
    return "passkey_enrollment_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: Record<string, unknown>
  ) {
    super(error_description);
    this.name = "PasskeyEnrollmentChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyEnrollmentChallengeError.prototype);
  }
}

/**
 * Thrown when verifying a passkey enrollment fails.
 *
 * Common causes:
 * - Invalid or expired auth_session
 * - Credential creation rejected
 * - Duplicate passkey (already registered)
 */
export class PasskeyEnrollmentVerifyError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: Record<string, unknown>;

  public get code(): string {
    return "passkey_enrollment_verify_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: Record<string, unknown>
  ) {
    super(error_description);
    this.name = "PasskeyEnrollmentVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyEnrollmentVerifyError.prototype);
  }
}
