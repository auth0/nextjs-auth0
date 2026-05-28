import { MyAccountApiError } from "./my-account-errors.js";
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
 * Thrown when passkey token exchange (POST /oauth/token with WebAuthn grant) fails.
 *
 * Common causes:
 * - Invalid or expired auth_session
 * - Credential assertion rejected by Auth0
 * - Passkey not recognized
 */
export class PasskeyGetTokenError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyApiErrorResponse;

  public get code(): string {
    return "passkey_get_token_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasskeyApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasskeyGetTokenError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
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
export class PasskeyEnrollmentChallengeError extends SdkError {
  public readonly code: string = "passkey_enrollment_challenge_error";
  public readonly cause?: MyAccountApiError;

  constructor(message: string, cause?: MyAccountApiError) {
    super(message);
    this.name = "PasskeyEnrollmentChallengeError";
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyEnrollmentChallengeError.prototype);
  }
}

/**
 * Thrown when verifying a passkey enrollment fails.
 * The MyAccount API returns errors in RFC 7807 problem detail format.
 *
 * Common causes:
 * - Invalid or expired auth_session
 * - Credential creation rejected
 * - Duplicate passkey (already registered)
 */
export class PasskeyEnrollmentVerifyError extends SdkError {
  public readonly code: string = "passkey_enrollment_verify_error";
  public readonly cause?: MyAccountApiError;

  constructor(message: string, cause?: MyAccountApiError) {
    super(message);
    this.name = "PasskeyEnrollmentVerifyError";
    this.cause = cause;
    Object.setPrototypeOf(this, PasskeyEnrollmentVerifyError.prototype);
  }
}
