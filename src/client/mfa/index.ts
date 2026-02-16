import {
  AccessTokenError,
  MfaChallengeError,
  MfaEnrollmentError,
  MfaGetAuthenticatorsError,
  MfaNoAvailableFactorsError,
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  MfaVerifyError
} from "../../errors/index.js";
import {
  ExecutionContextError,
  PopupBlockedError,
  PopupInProgressError
} from "../../errors/popup-errors.js";
import type { SdkError } from "../../errors/sdk-error.js";
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
import {
  DEFAULT_POPUP_HEIGHT,
  DEFAULT_POPUP_TIMEOUT,
  DEFAULT_POPUP_WIDTH,
  openCenteredPopup,
  waitForPopupCompletion
} from "../../utils/popup-helpers.js";
import {
  getAccessToken,
  type AccessTokenResponse
} from "../helpers/get-access-token.js";

/**
 * Client-side options for stepUpWithPopup()
 */
export interface StepUpWithPopupOptions {
  /** Target API audience (required) */
  audience: string;
  /** Space-separated scopes (optional, default: 'openid profile email') */
  scope?: string;
  /** ACR values for step-up (optional, default: MFA policy URI) */
  acr_values?: string;
  /** Return URL after authentication (optional, default: '/') */
  returnTo?: string;
  /** Timeout in milliseconds (optional, default: 60000) */
  timeout?: number;
  /** Popup window width (optional, default: 400) */
  popupWidth?: number;
  /** Popup window height (optional, default: 600) */
  popupHeight?: number;
}

// Singleton popup guard - prevents concurrent popups
let activePopup: Window | null = null;

/**
 * Parse error from postMessage payload into typed SdkError.
 * Called when popup sends {type: 'auth_complete', success: false, error: {...}}
 */
function parsePopupError(error: { code: string; message: string }): SdkError {
  const { code, message } = error;

  switch (code) {
    case "mfa_required":
      return new MfaRequiredError(message, "", undefined, undefined);
    case "access_denied":
      return new AccessTokenError(code, message, undefined);
    default:
      return new AccessTokenError(code, message, undefined);
  }
}

/**
 * Client-side MFA API (singleton).
 *
 * All operations are thin wrappers that fetch() to SDK routes.
 * Business logic executes server-side for security.
 *
 * @example React Component
 * ```typescript
 * 'use client';
 *
 * import { mfa } from '@auth0/nextjs-auth0/client';
 * import { useState } from 'react';
 *
 * export function MfaVerification({ mfaToken }) {
 *   const [otp, setOtp] = useState('');
 *   const [error, setError] = useState(null);
 *
 *   async function handleVerify() {
 *     try {
 *       await mfa.verify({ mfaToken, otp });
 *       window.location.href = '/dashboard'; // Redirect after success
 *     } catch (err) {
 *       setError(err.message);
 *     }
 *   }
 *
 *   return (
 *     <form onSubmit={e => { e.preventDefault(); handleVerify(); }}>
 *       <input value={otp} onChange={e => setOtp(e.target.value)} />
 *       <button type="submit">Verify</button>
 *       {error && <p>{error}</p>}
 *     </form>
 *   );
 * }
 * ```
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
   *
   * @example
   * ```typescript
   * 'use client';
   * import { mfa } from '@auth0/nextjs-auth0/client';
   * import { useState, useEffect } from 'react';
   *
   * export function AuthenticatorList({ mfaToken }) {
   *   const [authenticators, setAuthenticators] = useState([]);
   *
   *   useEffect(() => {
   *     mfa.getAuthenticators({ mfaToken })
   *       .then(setAuthenticators)
   *       .catch(console.error);
   *   }, [mfaToken]);
   *
   *   return (
   *     <ul>
   *       {authenticators.map(auth => (
   *         <li key={auth.id}>{auth.authenticatorType}</li>
   *       ))}
   *     </ul>
   *   );
   * }
   * ```
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
   *
   * @example
   * ```typescript
   * 'use client';
   * import { mfa } from '@auth0/nextjs-auth0/client';
   *
   * async function sendSmsCode(mfaToken, authenticatorId) {
   *   const challenge = await mfa.challenge({
   *     mfaToken,
   *     challengeType: 'oob',
   *     authenticatorId
   *   });
   *   // SMS sent, now collect binding code from user
   *   return challenge.oobCode;
   * }
   * ```
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
        mfaToken: options.mfaToken
      };

      // Type-based field mapping (matches VerifyMfaOptions union type)
      if ("otp" in options) {
        body.otp = options.otp;
      } else if ("oobCode" in options) {
        body.oobCode = options.oobCode;
        body.bindingCode = options.bindingCode;
      } else if ("recoveryCode" in options) {
        body.recoveryCode = options.recoveryCode;
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
   *
   * @example
   * ```typescript
   * 'use client';
   * import { mfa } from '@auth0/nextjs-auth0/client';
   * import QRCode from 'qrcode.react';
   *
   * export function EnrollOtp({ mfaToken }) {
   *   const [enrollment, setEnrollment] = useState(null);
   *
   *   async function handleEnroll() {
   *     const result = await mfa.enroll({
   *       mfaToken,
   *       authenticatorTypes: ['otp']
   *     });
   *     setEnrollment(result);
   *   }
   *
   *   return enrollment ? (
   *     <QRCode value={enrollment.barcodeUri} />
   *   ) : (
   *     <button onClick={handleEnroll}>Enroll</button>
   *   );
   * }
   * ```
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
   * Triggers MFA step-up authentication via Universal Login popup.
   * Opens popup window -> user completes MFA -> token cached in session -> returned.
   *
   * @param options - Configuration for the popup MFA flow
   * @returns AccessTokenResponse with the acquired token
   *
   * @throws ExecutionContextError - called in server/middleware context
   * @throws PopupBlockedError - browser blocks popup
   * @throws PopupInProgressError - another popup is already active
   * @throws PopupCancelledError - user closes popup
   * @throws PopupTimeoutError - popup doesn't complete within timeout
   * @throws AccessTokenError - token retrieval fails after popup
   * @throws MfaRequiredError - MFA is still required (shouldn't happen after popup)
   */
  async stepUpWithPopup(
    options: StepUpWithPopupOptions
  ): Promise<AccessTokenResponse> {
    // 1. Execution context guard
    if (typeof window === "undefined") {
      throw new ExecutionContextError(
        "stepUpWithPopup() can only be called in browser context"
      );
    }

    // 2. Concurrent popup guard (singleton)
    if (activePopup !== null && !activePopup.closed) {
      throw new PopupInProgressError();
    }

    // 3. Construct login URL with returnStrategy=postMessage
    const params = new URLSearchParams({
      returnTo: options.returnTo || "/",
      prompt: "login",
      acr_values:
        options.acr_values ||
        "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
      audience: options.audience,
      scope: options.scope || "openid profile email",
      returnStrategy: "postMessage"
    });

    const loginUrl =
      normalizeWithBasePath("/auth/login") + "?" + params.toString();

    // 4. Open centered popup
    const width = options.popupWidth || DEFAULT_POPUP_WIDTH;
    const height = options.popupHeight || DEFAULT_POPUP_HEIGHT;
    const popup = openCenteredPopup(loginUrl, width, height);

    if (popup === null) {
      throw new PopupBlockedError();
    }

    // 5. Track active popup (singleton guard)
    activePopup = popup;

    try {
      // 6. Wait for postMessage completion or timeout/cancel
      const timeout = options.timeout || DEFAULT_POPUP_TIMEOUT;
      const result = await waitForPopupCompletion(popup, timeout);

      // 7. Check postMessage result (discriminated union)
      if (!result.success) {
        throw parsePopupError(result.error);
      }

      // 8. Retrieve token from session via getAccessToken()
      //    mergeScopes: false prevents global scope pollution
      return (await getAccessToken({
        audience: options.audience,
        scope: options.scope || "openid profile email",
        mergeScopes: false,
        includeFullResponse: true
      })) as AccessTokenResponse;
    } finally {
      // 9. Cleanup: reset singleton guard
      activePopup = null;
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
    route: "getAuthenticators" | "challenge" | "verify" | "enroll",
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
    const isChallenge = route === "challenge" || url.includes("/challenge");
    const isVerify = route === "verify" || url.includes("/verify");
    const isEnroll = route === "enroll" || url.includes("/enroll");

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
export const mfa = new ClientMfaClient();
