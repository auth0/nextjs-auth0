import { SdkError } from "./sdk-error.js";

/**
 * Shape of an error response from the Auth0 Passwordless API.
 */
export interface PasswordlessApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for all passwordless-related errors.
 * Provides standardized JSON serialization matching Auth0 API format.
 *
 * Supports two consumption paths with identical shape:
 * 1. Direct SDK call: properties accessed on error instance
 * 2. HTTP API route: Response.json(error) uses toJSON() automatically
 */
abstract class PasswordlessError extends SdkError {
  public abstract readonly error: string;
  public abstract readonly error_description: string;

  toJSON(): { error: string; error_description: string } {
    return {
      error: this.error,
      error_description: this.error_description
    };
  }

  get code(): string {
    return this.error;
  }
}

/**
 * Thrown when initiating a passwordless flow via `/passwordless/start` fails.
 *
 * Common causes:
 * - Connection not enabled for the application
 * - Missing or invalid email / phone number
 * - Rate limit exceeded on send
 */
export class PasswordlessStartError extends PasswordlessError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasswordlessApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: PasswordlessApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasswordlessStartError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasswordlessStartError.prototype);
  }
}

/**
 * Thrown when verifying a passwordless OTP fails.
 *
 * Common causes:
 * - Invalid or expired OTP code
 * - Wrong connection / identifier combination
 */
export class PasswordlessVerifyError extends PasswordlessError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: PasswordlessApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: PasswordlessApiErrorResponse
  ) {
    super(error_description);
    this.name = "PasswordlessVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, PasswordlessVerifyError.prototype);
  }
}
