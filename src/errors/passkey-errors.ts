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
 * Thrown when requesting a passkey signup challenge fails.
 *
 * Common causes:
 * - Passkeys not enabled for the application
 * - Invalid client configuration
 */
export class PasskeySignupChallengeError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_signup_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeySignupChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeySignupChallengeError.prototype);
  }
}

/**
 * Thrown when requesting a passkey login challenge fails.
 *
 * Common causes:
 * - Passkeys not enabled for the application
 * - No passkey registered for the user
 */
export class PasskeyLoginChallengeError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_login_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyLoginChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyLoginChallengeError.prototype);
  }
}

/**
 * Thrown when passkey verification (token exchange) fails.
 *
 * Common causes:
 * - Invalid or expired auth_session
 * - Credential assertion rejected by Auth0
 * - Passkey not recognized
 */
export class PasskeyVerifyError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_verify_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyVerifyError.prototype);
  }
}

/**
 * Thrown when requesting a passkey enrollment challenge fails.
 *
 * Common causes:
 * - User not authenticated
 * - Insufficient scope (requires create:me:authentication_methods)
 * - Passkeys not enabled for the tenant
 */
export class PasskeyEnrollmentChallengeError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_enrollment_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
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
export class PasskeyEnrollVerifyError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_enroll_verify_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyEnrollVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyEnrollVerifyError.prototype);
  }
}
