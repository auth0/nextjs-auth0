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
 * Error response from the passkey token exchange, as returned by Auth0 and by the
 * SDK's `/auth/passkey/get-token` route.
 */
export interface PasskeyGetTokenApiErrorResponse extends PasskeyApiErrorResponse {
  /**
   * The auth session to retry with. Present only when the session is still alive
   * after a wrong verification code.
   */
  auth_session?: string;
  /** Identifiers that still need a valid verification code. Present with `auth_session`. */
  verification_required?: PasskeyVerificationIdentifier[];
  /** Set by the `/auth/passkey/get-token` route. Mirrors `PasskeyGetTokenError.isRetryable`. */
  is_retryable?: boolean;
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
 * During a signup with identifier verification, `isRetryable` is `true` only
 * when a code was wrong and the session is still alive: ask the user for the
 * codes in `verificationRequired` again and resubmit with `authSession` and the
 * same credential. `false` only means a new code will not help. It does not
 * mean the request can never be retried: a `too_many_requests` or server error
 * can succeed later. A missing or terminal session needs a new flow.
 */
export class PasskeyGetTokenError extends PasskeyError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasskeyGetTokenApiErrorResponse;
  /**
   * `true` when Auth0 returned `invalid_grant` with an `auth_session`: a
   * verification code was wrong but the session is alive. `false` for every
   * other failure, including a missing code (`invalid_request`), which carries
   * no `auth_session`. Branch on this, never on HTTP status or `error_description`,
   * which are identical on retryable and terminal `invalid_grant` responses.
   */
  public readonly isRetryable: boolean;
  /**
   * Session to resubmit against, set when Auth0 keeps it alive after a wrong
   * verification code. Never included in the message or `toJSON()`.
   */
  public readonly authSession?: string;
  /** Identifiers whose verification codes are still unverified. */
  public readonly verificationRequired?: PasskeyVerificationIdentifier[];

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
    this.authSession = cause?.auth_session;
    this.verificationRequired = cause?.verification_required;
    this.isRetryable = error === "invalid_grant" && !!cause?.auth_session;
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
