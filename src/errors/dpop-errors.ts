import { SdkError } from "./sdk-error.js";

/**
 * Error codes for DPoP-related errors.
 *
 * These error codes categorize different types of failures that can occur
 * during DPoP (Demonstrating Proof-of-Possession) operations.
 */
export enum DPoPErrorCode {
  /**
   * Failed to calculate dpop_jkt (JWK thumbprint) parameter.
   * This occurs when the SDK cannot generate the required thumbprint
   * from the provided public key for the authorization request.
   */
  DPOP_JKT_CALCULATION_FAILED = "dpop_jkt_calculation_failed",

  /**
   * Failed to export DPoP public key to JWK format.
   * This occurs when the SDK cannot convert the CryptoKey to the
   * JSON Web Key format required for DPoP proofs.
   */
  DPOP_KEY_EXPORT_FAILED = "dpop_key_export_failed",

  /**
   * DPoP configuration is invalid or incomplete.
   * This occurs when the provided DPoP configuration contains
   * invalid values or missing required components.
   */
  DPOP_CONFIGURATION_ERROR = "dpop_configuration_error"
}

/**
 * Represents an error that occurred during DPoP (Demonstrating Proof-of-Possession) operations.
 *
 * DPoP is an OAuth 2.0 extension that provides application-level proof-of-possession security
 * by binding access tokens to cryptographic key pairs. This error is thrown when DPoP-related
 * operations fail, such as key pair operations, proof generation, or configuration issues.
 *
 * Common scenarios that trigger DPoPError:
 * - Invalid or incompatible key pairs (wrong algorithm, corrupted keys)
 * - JWK thumbprint calculation failures
 * - Public key export failures to JWK format
 * - Invalid DPoP configuration parameters
 *
 * @example Handling DPoP errors
 * ```typescript
 * try {
 *   const auth0 = new Auth0Client({
 *     useDPoP: true,
 *     dpopKeyPair: invalidKeyPair
 *   });
 * } catch (error) {
 *   if (error instanceof DPoPError) {
 *     console.error(`DPoP Error [${error.code}]:`, error.message);
 *
 *     switch (error.code) {
 *       case DPoPErrorCode.DPOP_KEY_EXPORT_FAILED:
 *         console.error("Key export failed. Check key format and algorithm.");
 *         break;
 *       case DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED:
 *         console.error("JWK thumbprint calculation failed. Verify key validity.");
 *         break;
 *       case DPoPErrorCode.DPOP_CONFIGURATION_ERROR:
 *         console.error("Invalid DPoP configuration. Check options and environment variables.");
 *         break;
 *     }
 *
 *     if (error.cause) {
 *       console.error("Underlying cause:", error.cause);
 *     }
 *   }
 * }
 * ```
 *
 * @example Creating a DPoP error
 * ```typescript
 * throw new DPoPError(
 *   DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED,
 *   "Failed to calculate dpop_jkt parameter from public key",
 *   originalError
 * );
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
 */
export class DPoPError extends SdkError {
  /** The specific DPoP error code indicating the type of failure */
  public code: DPoPErrorCode;
  /** The underlying error that caused this DPoP error (optional) */
  public cause?: Error;

  /**
   * Constructs a new `DPoPError` instance.
   *
   * @param code - The DPoP error code indicating the specific type of failure
   * @param message - A descriptive error message explaining what went wrong
   * @param cause - The underlying error that caused this DPoP error (optional)
   *
   * @example
   * ```typescript
   * const dpopError = new DPoPError(
   *   DPoPErrorCode.DPOP_KEY_EXPORT_FAILED,
   *   "Unable to export public key to JWK format",
   *   keyExportError
   * );
   * ```
   */
  constructor(code: DPoPErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = "DPoPError";
    this.code = code;
    this.cause = cause;
  }
}
