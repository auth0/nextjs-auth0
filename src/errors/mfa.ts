import { SdkError, type OAuth2Error } from "./index.js";

/**
 * Error thrown when getting MFA authenticators fails.
 * Mirrors Auth0 API error format exactly.
 */
export class MfaGetAuthenticatorsError extends SdkError {
  public readonly error: string;
  public readonly error_description: string;

  constructor(
    error: string,
    error_description: string,
    public cause?: OAuth2Error | Error
  ) {
    super(error_description);
    this.name = "MfaGetAuthenticatorsError";
    this.error = error;
    this.error_description = error_description;
    Object.setPrototypeOf(this, MfaGetAuthenticatorsError.prototype);
  }

  get code(): string {
    return this.error;
  }
}

/**
 * Error thrown when initiating an MFA challenge fails.
 * Mirrors Auth0 API error format exactly.
 */
export class MfaChallengeError extends SdkError {
  public readonly error: string;
  public readonly error_description: string;

  constructor(
    error: string,
    error_description: string,
    public cause?: OAuth2Error | Error
  ) {
    super(error_description);
    this.name = "MfaChallengeError";
    this.error = error;
    this.error_description = error_description;
    Object.setPrototypeOf(this, MfaChallengeError.prototype);
  }

  get code(): string {
    return this.error;
  }
}

/**
 * Error thrown when MFA verification fails.
 * Mirrors Auth0 API error format exactly.
 */
export class MfaVerifyError extends SdkError {
  public readonly error: string;
  public readonly error_description: string;

  constructor(
    error: string,
    error_description: string,
    public cause?: OAuth2Error | Error
  ) {
    super(error_description);
    this.name = "MfaVerifyError";
    this.error = error;
    this.error_description = error_description;
    Object.setPrototypeOf(this, MfaVerifyError.prototype);
  }

  get code(): string {
    return this.error;
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
