import { SdkError } from "./sdk-error.js";

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
 * Thrown when request validation fails (missing/invalid params).
 * Mapped to 400 Bad Request.
 */
export class InvalidRequestError extends SdkError {
  public code = "invalid_request";

  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
    this.name = "InvalidRequestError";
  }

  toJSON() {
    return {
      error: this.code,
      error_description: this.message
    };
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
 * MFA requirements from an mfa_required error response.
 * Indicates which MFA methods are available for the user.
 * Matches Auth0 API response shape and auth0-spa-js type.
 */
export interface MfaRequirements {
  /** Required enrollment types (user needs to enroll new authenticator) */
  enroll?: Array<{ type: string }>;
  /** Available challenge types (existing authenticators) */
  challenge?: Array<{ type: string }>;
}

/**
 * Thrown when {@link getAccessToken} requires MFA step-up authentication.
 *
 * This error is thrown during token refresh when Auth0 returns `mfa_required`.
 * The {@link mfa_token} property contains an encrypted token that can be used
 * with Auth0's MFA API to complete the authentication challenge.
 *
 * @remarks
 * The `mfa_token` is encrypted using the SDK's cookie secret for security.
 * The raw token from Auth0 is never exposed to application code.
 *
 * Supports two consumption paths with identical shape:
 * 1. Direct SDK call: properties accessed on error instance
 * 2. HTTP API route: Response.json(error) uses toJSON() automatically
 *
 * @example Handling MFA required in a route handler
 * ```typescript
 * import { getAccessToken, MfaRequiredError } from "@auth0/nextjs-auth0/server";
 *
 * try {
 *   const { token } = await getAccessToken({ audience: "https://api.example.com" });
 * } catch (error) {
 *   if (error instanceof MfaRequiredError) {
 *     // Redirect to MFA challenge page
 *     redirect(`/mfa?token=${error.mfa_token}`);
 *   }
 *   throw error;
 * }
 * ```
 *
 * @see {@link https://auth0.com/docs/api/authentication#multi-factor-authentication Auth0 MFA API}
 */
export class MfaRequiredError extends SdkError {
  public readonly code: string = "mfa_required";

  /**
   * Encrypted MFA token to pass to MFA API methods.
   */
  public readonly mfa_token: string;

  /** Original Auth0 error code */
  public readonly error: string = "mfa_required";

  /** Original Auth0 error description */
  public readonly error_description: string;

  /** MFA requirements indicating available challenge/enrollment methods */
  public readonly mfa_requirements?: MfaRequirements;

  public readonly cause?: Error;

  /**
   * @param error_description - Error description from Auth0
   * @param mfaToken - Encrypted MFA token (constructor param uses camelCase)
   * @param mfaRequirements - MFA requirements from Auth0 (constructor param uses camelCase)
   * @param cause - Underlying error
   *
   * @remarks
   * Constructor parameters use camelCase (mfaToken, mfaRequirements) for consistency
   * with SDK conventions, but they are assigned to snake_case properties (mfa_token,
   * mfa_requirements) to match Auth0 API response format.
   */
  constructor(
    error_description: string,
    mfaToken: string,
    mfaRequirements?: MfaRequirements,
    cause?: Error
  ) {
    super(error_description);
    this.name = "MfaRequiredError";
    this.error_description = error_description;
    this.mfa_token = mfaToken;
    this.mfa_requirements = mfaRequirements;
    this.cause = cause;
  }

  /**
   * Serialize error for HTTP responses.
   * Called automatically by Response.json() and JSON.stringify().
   * Ensures both SDK and HTTP API consumers get identical shape.
   */
  toJSON(): {
    error: string;
    error_description: string;
    mfa_token: string;
    mfa_requirements?: MfaRequirements;
  } {
    return {
      error: this.error,
      error_description: this.error_description,
      mfa_token: this.mfa_token,
      ...(this.mfa_requirements && { mfa_requirements: this.mfa_requirements })
    };
  }
}

/**
 * Thrown when MFA API methods are called but no context exists in session
 * for the provided encrypted mfa_token.
 *
 * This typically occurs when:
 * - The session expired between catching MfaRequiredError and calling MFA methods
 * - The mfa_token was modified or is from a different session
 * - The MFA context was cleaned up due to TTL expiration
 *
 * @example
 * ```typescript
 * try {
 *   await auth0.completeMfaChallenge(mfaToken, code);
 * } catch (error) {
 *   if (error instanceof MfaTokenNotFoundError) {
 *     // Restart MFA flow - context was lost
 *     redirect("/auth/login?prompt=mfa");
 *   }
 * }
 * ```
 */
export class MfaTokenExpiredError extends SdkError {
  public readonly code: string = "mfa_token_expired";

  constructor() {
    super("MFA token has expired. Please restart the MFA flow.");
    this.name = "MfaTokenExpiredError";
  }
}

/**
 * Thrown when the encrypted mfa_token is invalid.
 *
 * This occurs when:
 * - The token was tampered with
 * - The token is malformed (not valid JWE)
 * - The token was encrypted with a different secret
 */
export class MfaTokenInvalidError extends SdkError {
  public readonly code: string = "mfa_token_invalid";

  constructor() {
    super("MFA token is invalid.");
    this.name = "MfaTokenInvalidError";
  }
}
