import { type PasswordlessApiErrorResponse } from "./passwordless-errors.js";
import { SdkError } from "./sdk-error.js";

abstract class PasswordlessDbError extends SdkError {
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
 * Thrown when a `POST /otp/challenge` request fails.
 *
 * Common causes:
 * - OTP grant type not enabled on the application
 * - Connection is not a database connection (`invalid_connection`)
 * - OTP not configured on the connection (`invalid_connection`)
 * - Phone provider not configured when using phone OTP
 * - Missing or invalid identifier
 */
export class PasswordlessDbChallengeError extends PasswordlessDbError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasswordlessApiErrorResponse;

  public get code(): string {
    return "passwordless_challenge_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasswordlessApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasswordlessDbChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasswordlessDbChallengeError.prototype);
  }
}

/**
 * Thrown when a `POST /oauth/token` OTP exchange fails.
 *
 * Common causes:
 * - Invalid or expired OTP code (`invalid_request`)
 * - Wrong or expired `auth_session` (`invalid_request`)
 * - Blocked user or signup disabled for a non-existent user (`invalid_request`)
 * - Discovery failure (`discovery_error`)
 */
export class PasswordlessDbGetTokenError extends PasswordlessDbError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasswordlessApiErrorResponse;

  public get code(): string {
    return "passwordless_login_error";
  }

  constructor(
    error: string,
    error_description: string,
    cause?: PasswordlessApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasswordlessDbGetTokenError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasswordlessDbGetTokenError.prototype);
  }
}
