/**
 * MCD (Multiple Custom Domains) specific error classes.
 *
 * Note: `BackchannelLogoutError` is renamed with `Mcd` prefix to avoid
 * collision with the identically-named class in `oauth-errors.ts`.
 * MCD configuration errors use the shared `InvalidConfigurationError`
 * from `oauth-errors.ts`.
 *
 * @module errors/mcd
 */

import { SdkError } from "./sdk-error.js";

/**
 * Error thrown when domain resolution fails during MCD initialization or request handling.
 *
 * This error is public and may be caught by application code.
 *
 * @public
 */
export class DomainResolutionError extends SdkError {
  public code: string = "domain_resolution_error";

  /**
   * Creates a new DomainResolutionError instance.
   *
   * @param message - A descriptive error message
   * @param cause - The underlying error that caused the resolution failure (optional)
   */
  constructor(
    message?: string,
    public cause?: Error
  ) {
    super(message ?? "Failed to resolve the domain from the request.");
    this.name = "DomainResolutionError";
  }
}

/**
 * Error thrown when a domain hostname fails validation.
 *
 * This includes rejection of IP addresses, localhost, .local domains, paths, and ports.
 * This error is public and may be caught by application code.
 *
 * @public
 */
export class DomainValidationError extends SdkError {
  public code: string = "domain_validation_error";

  /**
   * Creates a new DomainValidationError instance.
   *
   * @param message - A descriptive error message
   */
  constructor(message?: string) {
    super(message ?? "The domain failed validation.");
    this.name = "DomainValidationError";
  }
}

/**
 * Error thrown when the issuer URL is invalid or cannot be resolved.
 *
 * This error is public and may be caught by application code.
 *
 * @public
 */
export class IssuerValidationError extends SdkError {
  public code: string = "issuer_validation_error";

  /**
   * Creates a new IssuerValidationError instance.
   *
   * @param expectedIssuer - The expected issuer URL
   * @param actualIssuer - The actual issuer URL from the token
   */
  constructor(
    public expectedIssuer: string,
    public actualIssuer: string
  ) {
    super(
      `Issuer Mismatch: expected "${expectedIssuer}" but received "${actualIssuer}"`
    );
    this.name = "IssuerValidationError";
  }
}

/**
 * Error thrown when a session's domain does not match the current request domain.
 *
 * This indicates a potential security issue where a user is attempting to use a session
 * created for a different domain.
 *
 * @public
 */
export class SessionDomainMismatchError extends SdkError {
  public code: string = "session_domain_mismatch";

  /**
   * Creates a new SessionDomainMismatchError instance.
   *
   * @param message - A descriptive error message
   */
  constructor(message?: string) {
    super(
      message ?? "The session domain does not match the current request domain."
    );
    this.name = "SessionDomainMismatchError";
  }
}
