import {
  MfaChallengeError,
  MfaDeleteAuthenticatorError,
  MfaEnrollmentError,
  MfaGetAuthenticatorsError,
  MfaNoAvailableFactorsError,
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  MfaVerifyError
} from "../../errors/index.js";
import type {
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  EnrollOptions,
  MfaClient,
  MfaVerifyResponse,
  VerifyMfaOptions
} from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Client-side MFA API (singleton).
 * Thin wrappers that fetch() to SDK routes.
 * All business logic executes server-side.
 */
class ClientMfaClient implements MfaClient {
  /**
   * List enrolled MFA authenticators.
   *
   * Server-side logic:
   * - Decrypts mfaToken (validates TTL and integrity)
   * - Calls Auth0 API with raw mfa_token
   * - Filters by allowed challenge types
   * - Returns array of authenticators
   *
   * @param options - Options containing encrypted mfaToken
   * @returns Array of available authenticators
   * @throws {MfaTokenExpiredError} Token TTL exceeded
   * @throws {MfaTokenInvalidError} Token tampered or malformed
   * @throws {MfaGetAuthenticatorsError} Auth0 API error
   */
  async getAuthenticators(options: {
    mfaToken: string;
  }): Promise<Authenticator[]> {
    try {
      const urlParams = new URLSearchParams();
      urlParams.append("mfa_token", options.mfaToken);

      const url = `${normalizeWithBasePath(
        process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE ||
          "/auth/mfa/authenticators"
      )}?${urlParams.toString()}`;

      const response = await fetch(url, {
        method: "GET",
        credentials: "omit" // Stateless operation, no session needed
      });

      if (!response.ok) {
        const error = await response.json();
        throw this.parseError(error, "getAuthenticators", response.url);
      }

      return await response.json();
    } catch (e) {
      // Re-throw typed errors
      if (
        e instanceof MfaTokenExpiredError ||
        e instanceof MfaTokenInvalidError ||
        e instanceof MfaGetAuthenticatorsError
      ) {
        throw e;
      }

      // Network/parse errors → MfaGetAuthenticatorsError with client_error code
      throw new MfaGetAuthenticatorsError(
        "client_error",
        e instanceof Error ? e.message : "Network or parsing error",
        undefined
      );
    }
  }

  /**
   * Initiate an MFA challenge.
   *
   * Server-side logic:
   * - Decrypts mfaToken (validates TTL and integrity)
   * - Calls Auth0 challenge API
   * - Returns challenge response (oobCode, bindingMethod)
   *
   * @param options - Challenge options
   * @returns Challenge response with oobCode and bindingMethod
   * @throws {MfaTokenExpiredError} Token TTL exceeded
   * @throws {MfaTokenInvalidError} Token tampered or malformed
   * @throws {MfaChallengeError} Auth0 API error
   */
  async challenge(options: {
    mfaToken: string;
    challengeType: string;
    authenticatorId?: string;
  }): Promise<ChallengeResponse> {
    try {
      const body: Record<string, string> = {
        mfaToken: options.mfaToken,
        challengeType: options.challengeType
      };

      if (options.authenticatorId) {
        body.authenticatorId = options.authenticatorId;
      }

      const url = normalizeWithBasePath(
        process.env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE || "/auth/mfa/challenge"
      );

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "omit", // Stateless operation
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        const error = await response.json();
        throw this.parseError(error, "challenge", response.url);
      }

      return await response.json();
    } catch (e) {
      // Re-throw typed errors
      if (
        e instanceof MfaTokenExpiredError ||
        e instanceof MfaTokenInvalidError ||
        e instanceof MfaChallengeError
      ) {
        throw e;
      }

      // Network/parse errors
      throw new MfaChallengeError(
        "client_error",
        e instanceof Error ? e.message : "Network or parsing error",
        undefined
      );
    }
  }

  /**
   * Verify MFA code and complete authentication.
   *
   * Server-side logic:
   * - Decrypts mfaToken (validates TTL and integrity)
   * - Calls Auth0 verify API
   * - Caches resulting access token in session
   * - Returns token response
   *
   * Chained MFA: If Auth0 returns mfa_required, throws MfaRequiredError with
   * a new encrypted mfa_token for the next factor.
   *
   * @param options - Verification options (otp, oobCode+bindingCode, or recoveryCode)
   * @returns Token response with access_token, refresh_token, etc.
   * @throws {MfaTokenExpiredError} Token TTL exceeded
   * @throws {MfaTokenInvalidError} Token tampered or malformed
   * @throws {MfaRequiredError} Additional MFA factor required (chained MFA)
   * @throws {MfaVerifyError} Auth0 API error (wrong code, rate limit, etc.)
   */
  async verify(options: VerifyMfaOptions): Promise<MfaVerifyResponse> {
    try {
      const body: Record<string, string> = {
        mfa_token: options.mfaToken
      };

      // Type-based field mapping (matches VerifyMfaOptions union type)
      if ("otp" in options) {
        body.otp = options.otp;
      } else if ("oobCode" in options) {
        body.oob_code = options.oobCode;
        body.binding_code = options.bindingCode;
      } else if ("recoveryCode" in options) {
        body.recovery_code = options.recoveryCode;
      }

      const url = normalizeWithBasePath(
        process.env.NEXT_PUBLIC_MFA_VERIFY_ROUTE || "/auth/mfa/verify"
      );

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include", // Session caching (verify stores token in session)
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        const error = await response.json();
        throw this.parseError(error, "verify", response.url);
      }

      return await response.json();
    } catch (e) {
      // Re-throw typed errors
      if (
        e instanceof MfaTokenExpiredError ||
        e instanceof MfaTokenInvalidError ||
        e instanceof MfaRequiredError ||
        e instanceof MfaVerifyError
      ) {
        throw e;
      }

      // Network/parse errors
      throw new MfaVerifyError(
        "client_error",
        e instanceof Error ? e.message : "Network or parsing error",
        undefined
      );
    }
  }

  /**
   * Delete an enrolled MFA authenticator.
   *
   * Server-side logic:
   * - Decrypts mfaToken (validates TTL and integrity)
   * - Calls Auth0 DELETE /mfa/authenticators/{id} API
   * - Returns 204 on success
   *
   * @param options - Delete options containing encrypted mfaToken and authenticatorId
   * @returns Promise that resolves when deletion succeeds
   * @throws {MfaTokenExpiredError} Token TTL exceeded
   * @throws {MfaTokenInvalidError} Token tampered or malformed
   * @throws {MfaDeleteAuthenticatorError} Auth0 API error
   */
  async deleteAuthenticator(options: {
    mfaToken: string;
    authenticatorId: string;
  }): Promise<void> {
    try {
      const url = normalizeWithBasePath(
        `${
          process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE ||
          "/auth/mfa/authenticators"
        }/${options.authenticatorId}`
      );

      const response = await fetch(url, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${options.mfaToken}`
        },
        credentials: "omit" // Stateless operation
      });

      if (!response.ok) {
        const error = await response.json();
        throw this.parseError(error, "deleteAuthenticator", response.url);
      }

      // Success: 204 No Content
    } catch (e) {
      // Re-throw typed errors
      if (
        e instanceof MfaTokenExpiredError ||
        e instanceof MfaTokenInvalidError ||
        e instanceof MfaDeleteAuthenticatorError
      ) {
        throw e;
      }

      // Network/parse errors
      throw new MfaDeleteAuthenticatorError(
        "client_error",
        e instanceof Error ? e.message : "Network or parsing error",
        undefined
      );
    }
  }

  /**
   * Enroll a new MFA authenticator.
   *
   * Server-side logic:
   * - Decrypts mfaToken (validates TTL and integrity)
   * - Calls Auth0 enrollment API
   * - Returns enrollment response with authenticator details and optional recovery codes
   *
   * @param options - Enrollment options (otp | oob | email)
   * @returns Enrollment response with authenticator ID, secret (for OTP), and optional recovery codes
   * @throws {MfaTokenExpiredError} Token TTL exceeded
   * @throws {MfaTokenInvalidError} Token tampered or malformed
   * @throws {MfaEnrollmentError} Auth0 API error
   */
  async enroll(options: EnrollOptions): Promise<EnrollmentResponse> {
    try {
      const url = normalizeWithBasePath(
        process.env.NEXT_PUBLIC_MFA_ENROLL_ROUTE || "/auth/mfa/enroll"
      );

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(options),
        credentials: "omit" // Stateless operation
      });

      if (!response.ok) {
        const error = await response.json();
        throw this.parseError(error, "enroll", response.url);
      }

      return await response.json();
    } catch (e) {
      // Re-throw typed errors
      if (
        e instanceof MfaTokenExpiredError ||
        e instanceof MfaTokenInvalidError ||
        e instanceof MfaEnrollmentError
      ) {
        throw e;
      }

      // Network/parse errors
      throw new MfaEnrollmentError(
        "client_error",
        e instanceof Error ? e.message : "Network or parsing error",
        undefined
      );
    }
  }

  /**
   * Parse server error response into typed error classes.
   *
   * Server returns JSON: { error, error_description, mfa_token? }
   * Maps to SDK error types based on error code and route context.
   *
   * Chained MFA: error === 'mfa_required' → MfaRequiredError (not MfaVerifyError)
   *
   * @param error - Parsed JSON error from server
   * @param route - Route name for fallback error detection
   * @param url - Full URL for route extraction
   * @returns Typed error instance
   */
  private parseError(
    error: Record<string, any>,
    route:
      | "getAuthenticators"
      | "challenge"
      | "verify"
      | "deleteAuthenticator"
      | "enroll",
    url: string
  ): Error {
    const code = error.error || "unknown_error";
    const description = error.error_description || "Unknown error occurred";

    // SDK errors (fixed codes)
    if (code === "mfa_token_expired") {
      return new MfaTokenExpiredError();
    }
    if (code === "mfa_token_invalid") {
      return new MfaTokenInvalidError();
    }
    if (code === "mfa_no_available_factors") {
      return new MfaNoAvailableFactorsError(description);
    }

    // Chained MFA: mfa_required means "success, continue to next factor"
    // NOT a verification failure, so use MfaRequiredError (not MfaVerifyError)
    if (code === "mfa_required") {
      return new MfaRequiredError(
        description,
        error.mfa_token, // Server returns encrypted token for next factor
        error.mfa_requirements,
        undefined
      );
    }

    // Auth0 API errors (dynamic codes) - route-based fallback
    // Route detection from URL (fallback if route param is unreliable)
    const isAuthenticators =
      route === "getAuthenticators" || url.includes("/authenticators");
    const isDeleteAuthenticator =
      route === "deleteAuthenticator" || url.includes("/authenticators/");
    const isChallenge = route === "challenge" || url.includes("/challenge");
    const isVerify = route === "verify" || url.includes("/verify");
    const isEnroll = route === "enroll" || url.includes("/enroll");

    if (isDeleteAuthenticator) {
      return new MfaDeleteAuthenticatorError(code, description, undefined);
    }
    if (isAuthenticators) {
      return new MfaGetAuthenticatorsError(code, description, undefined);
    }
    if (isChallenge) {
      return new MfaChallengeError(code, description, undefined);
    }
    if (isVerify) {
      return new MfaVerifyError(code, description, undefined);
    }
    if (isEnroll) {
      return new MfaEnrollmentError(code, description, undefined);
    }

    // Fallback: unknown route (shouldn't happen)
    return new MfaVerifyError(code, description, undefined);
  }
}

/**
 * Client-side MFA API singleton.
 *
 * @example
 * ```typescript
 * import { mfa } from '@auth0/nextjs-auth0/client';
 *
 * // List authenticators
 * const authenticators = await mfa.getAuthenticators({ mfaToken });
 *
 * // Initiate challenge
 * const challenge = await mfa.challenge({ mfaToken, challengeType: 'oob' });
 *
 * // Verify and complete
 * const tokens = await mfa.verify({ mfaToken, otp: '123456' });
 * ```
 */
export const mfa: MfaClient = new ClientMfaClient();
