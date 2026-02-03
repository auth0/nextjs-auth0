import { SdkError } from "./index.js";

/**
 * Interface for Auth0 MFA API error responses.
 * All MFA errors from Auth0 follow this shape (snake_case).
 */
export interface MfaApiErrorResponse {
  error: string;
  error_description: string;
  message?: string;
}

/**
 * Base class for all MFA-related errors.
 * Provides standardized JSON serialization matching Auth0 API format.
 *
 * Supports two consumption paths with identical shape:
 * 1. Direct SDK call: properties accessed on error instance
 * 2. HTTP API route: Response.json(error) uses toJSON() automatically
 *
 * @example
 * ```typescript
 * try {
 *   await mfa.getAuthenticators({ mfaToken });
 * } catch (error) {
 *   if (error instanceof MfaError) {
 *     return Response.json(error, { status: 400 });
 *   }
 * }
 * ```
 */
abstract class MfaError extends SdkError {
  public abstract readonly error: string;
  public abstract readonly error_description: string;

  /**
   * Serialize error for HTTP responses.
   * Called automatically by Response.json() and JSON.stringify().
   * Ensures both SDK and HTTP API consumers get identical shape.
   */
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
 * Error thrown when listing MFA authenticators fails.
 *
 * @example
 * ```typescript
 * try {
 *   const authenticators = await mfa.getAuthenticators({ mfaToken });
 * } catch (error) {
 *   if (error instanceof MfaGetAuthenticatorsError) {
 *     console.error(error.code); // 'invalid_token', 'expired_token', etc.
 *     console.error(error.cause?.error_description);
 *   }
 * }
 * ```
 */
export class MfaGetAuthenticatorsError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: MfaApiErrorResponse
  ) {
    super(error_description);
    this.name = "MfaGetAuthenticatorsError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaGetAuthenticatorsError.prototype);
  }
}

/**
 * Error thrown when initiating an MFA challenge fails.
 *
 * @example
 * ```typescript
 * try {
 *   await mfa.challenge({
 *     mfaToken,
 *     challengeType: 'oob',
 *     authenticatorId: 'sms|dev_abc123'
 *   });
 * } catch (error) {
 *   if (error instanceof MfaChallengeError) {
 *     if (error.cause?.error === 'invalid_authenticator_id') {
 *       console.error('Authenticator not found or not active');
 *     }
 *   }
 * }
 * ```
 */
export class MfaChallengeError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: MfaApiErrorResponse
  ) {
    super(error_description);
    this.name = "MfaChallengeError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaChallengeError.prototype);
  }
}

/**
 * Error thrown when MFA verification fails.
 *
 * @example
 * ```typescript
 * try {
 *   await mfa.verify({
 *     mfaToken,
 *     otp: '123456'
 *   });
 * } catch (error) {
 *   if (error instanceof MfaVerifyError) {
 *     if (error.cause?.error === 'invalid_grant') {
 *       console.error('Invalid or expired verification code');
 *     }
 *   }
 * }
 * ```
 */
export class MfaVerifyError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: MfaApiErrorResponse
  ) {
    super(error_description);
    this.name = "MfaVerifyError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaVerifyError.prototype);
  }
}

/**
 * Error thrown when no MFA factors are available for challenge.
 * SDK-generated error (no Auth0 API equivalent).
 */
export class MfaNoAvailableFactorsError extends SdkError {
  public readonly code: string = "mfa_no_available_factors";
  public readonly error: string = "mfa_no_available_factors";
  public readonly error_description: string;

  constructor(error_description: string) {
    super(error_description);
    this.name = "MfaNoAvailableFactorsError";
    this.error_description = error_description;
    Object.setPrototypeOf(this, MfaNoAvailableFactorsError.prototype);
  }
}

/**
 * Error thrown when MFA enrollment fails.
 *
 * @example
 * ```typescript
 * try {
 *   await mfa.enroll({
 *     mfaToken,
 *     authenticatorTypes: ['otp']
 *   });
 * } catch (error) {
 *   if (error instanceof MfaEnrollmentError) {
 *     if (error.cause?.error === 'unsupported_challenge_type') {
 *       console.error('Tenant does not support OTP enrollment');
 *     }
 *   }
 * }
 * ```
 */
export class MfaEnrollmentError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: MfaApiErrorResponse
  ) {
    super(error_description);
    this.name = "MfaEnrollmentError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaEnrollmentError.prototype);
  }
}

/**
 * Error thrown when deleting an MFA authenticator fails.
 *
 * @example
 * ```typescript
 * try {
 *   await mfa.deleteAuthenticator({
 *     mfaToken,
 *     authenticatorId: 'totp|dev_abc123'
 *   });
 * } catch (error) {
 *   if (error instanceof MfaDeleteAuthenticatorError) {
 *     if (error.cause?.error === 'authenticator_not_found') {
 *       console.error('Authenticator already deleted or invalid ID');
 *     }
 *   }
 * }
 * ```
 */
export class MfaDeleteAuthenticatorError extends MfaError {
  public readonly error: string;
  public readonly error_description: string;
  public readonly cause?: MfaApiErrorResponse;

  constructor(
    error: string,
    error_description: string,
    cause?: MfaApiErrorResponse
  ) {
    super(error_description);
    this.name = "MfaDeleteAuthenticatorError";
    this.error = error;
    this.error_description = error_description;
    this.cause = cause;
    Object.setPrototypeOf(this, MfaDeleteAuthenticatorError.prototype);
  }
}
