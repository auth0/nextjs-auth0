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
 * Options for {@link ClientMfaClient.challengeWithPopup | mfa.challengeWithPopup()}.
 *
 * Controls the popup MFA step-up flow: which API audience to target,
 * scopes to request, and popup window behavior.
 *
 * @example
 * ```typescript
 * const { token } = await mfa.challengeWithPopup({
 *   audience: 'https://api.example.com',
 *   scope: 'openid profile email read:sensitive',
 *   timeout: 120000,
 *   popupWidth: 500,
 *   popupHeight: 700
 * });
 * ```
 */
export interface ChallengeWithPopupOptions {
  /** Target API audience (required) */
  audience: string;
  /** Space-separated scopes (optional — inherits global config when omitted) */
  scope?: string;
  /** ACR values for step-up (optional, default: MFA policy URI) */
  acr_values?: string;
  /**
   * OIDC `prompt` parameter (optional, default: not sent).
   *
   * When omitted, Auth0 will use the existing session and skip straight to
   * the MFA challenge if the user is already authenticated. Set to `"login"`
   * to force full re-authentication (username + password + MFA).
   */
  prompt?: string;
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
   * Triggers MFA step-up authentication via a Universal Login popup.
   *
   * Opens a centered popup window that navigates to `/auth/login` with
   * `returnStrategy=postMessage`. The user completes MFA through Auth0's
   * Universal Login in the popup. On completion, the popup sends a
   * `postMessage` back to the parent window, and the SDK retrieves the
   * cached access token from the server session.
   *
   * **Important:** Must be called from a user-initiated event handler
   * (e.g., click) to avoid browser popup blockers.
   *
   * @param options - Configuration for the popup MFA flow
   * @returns Access token response with token, scope, and expiry metadata
   *
   * @throws {ExecutionContextError} Called in server/middleware context (requires `window`)
   * @throws {PopupBlockedError} Browser blocked the popup (not user-initiated or popups disabled)
   * @throws {PopupInProgressError} Another `challengeWithPopup()` call is already active
   * @throws {PopupCancelledError} User manually closed the popup window
   * @throws {PopupTimeoutError} Popup did not complete within the configured timeout
   * @throws {AccessTokenError} Token retrieval from session failed after popup completed
   * @throws {MfaRequiredError} MFA is still required (unexpected after successful popup)
   *
   * @example
   * ```typescript
   * 'use client';
   * import { mfa, getAccessToken } from '@auth0/nextjs-auth0/client';
   * import { MfaRequiredError } from '@auth0/nextjs-auth0/errors';
   *
   * async function fetchProtectedData() {
   *   try {
   *     return await getAccessToken({ audience: 'https://api.example.com' });
   *   } catch (err) {
   *     if (err instanceof MfaRequiredError) {
   *       const { token } = await mfa.challengeWithPopup({
   *         audience: 'https://api.example.com'
   *       });
   *       return token;
   *     }
   *     throw err;
   *   }
   * }
   * ```
   */
  async challengeWithPopup(
    options: ChallengeWithPopupOptions
  ): Promise<AccessTokenResponse> {
    // 1. Execution context guard
    if (typeof window === "undefined") {
      throw new ExecutionContextError(
        "challengeWithPopup() can only be called in browser context"
      );
    }

    // 2. Concurrent popup guard (singleton)
    if (activePopup !== null && !activePopup.closed) {
      throw new PopupInProgressError();
    }

    // 3. Construct login URL with returnStrategy=postMessage
    const params = new URLSearchParams({
      returnTo: options.returnTo || "/",
      acr_values:
        options.acr_values ||
        "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
      audience: options.audience,
      returnStrategy: "postMessage"
    });
    // Only include prompt when explicitly provided. Omitting it lets Auth0
    // recognise the existing session and skip straight to the MFA challenge
    // instead of showing the full login screen again.
    if (options.prompt) {
      params.set("prompt", options.prompt);
    }
    // Only override scope if the caller explicitly provided one.
    // When omitted, startInteractiveLogin uses the global scope config,
    // so transactionState.scope matches what a default getAccessToken()
    // lookup computes — preventing cache misses on subsequent calls.
    // See session-helpers.ts for detailed explanation of why
    // requestedScope must use transactionState.scope (not oidcRes.scope).
    if (options.scope) {
      params.set("scope", options.scope);
    }

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
      // When caller provided explicit scope: use mergeScopes:false for
      // precise lookup matching exactly what was stored.
      // When no explicit scope: use default behavior (server merges global
      // scopes) so the lookup key matches what the popup flow stored
      // in transactionState.scope (which inherited global scopes).
      // See session-helpers.ts for the full requestedScope rationale.
      return (await getAccessToken({
        audience: options.audience,
        includeFullResponse: true,
        ...(options.scope ? { scope: options.scope, mergeScopes: false } : {})
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
 * Provides methods for MFA authenticator management, challenge/verify flows,
 * and popup-based step-up authentication via Universal Login.
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
 *
 * // Step-up via popup (no redirect)
 * const { token } = await mfa.challengeWithPopup({
 *   audience: 'https://api.example.com'
 * });
 * ```
 */
export const mfa = new ClientMfaClient();
