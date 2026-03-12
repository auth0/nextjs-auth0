import { generateKeyPair, isDPoPNonceError } from "oauth4webapi";
import { DpopKeyPair, RetryConfig } from "../types/dpop.js";

/**
 * Detects if the current environment is Edge Runtime.
 * Edge Runtime environments have limited Node.js API support.
 */
export function isEdgeRuntime(): boolean {
  return typeof (globalThis as any).EdgeRuntime === "string";
}

/**
 * Generates a new ES256 key pair for DPoP (Demonstrating Proof-of-Possession) operations.
 *
 * This function creates a cryptographically secure ES256 key pair suitable for DPoP proof
 * generation. The generated keys use the P-256 elliptic curve with SHA-256 hashing,
 * which is the required algorithm for DPoP as specified in RFC 9449.
 *
 * @returns Promise that resolves to a DpopKeyPair containing the private and public keys
 *
 * @example
 * ```typescript
 * import { generateDpopKeyPair } from "@auth0/nextjs-auth0/server";
 *
 * const keyPair = await generateDpopKeyPair();
 *
 * const auth0 = new Auth0Client({
 *   useDPoP: true,
 *   dpopKeyPair: keyPair
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
 */
export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}

const applyRetryDelay = async (config?: RetryConfig) => {
  const delay = config?.delay ?? 100;
  const jitter = config?.jitter ?? true;
  let actualDelay = delay;
  // Apply jitter if enabled (50-100% of original delay to prevent thundering herd)
  if (jitter) {
    actualDelay = delay * (0.5 + Math.random() * 0.5);
  }
  // Delay before retry to avoid rapid successive requests
  await new Promise((resolve) => setTimeout(resolve, actualDelay));
};

/**
 * Executes a function with retry logic for DPoP nonce errors.
 *
 * DPoP nonce errors occur when the authorization server requires a fresh nonce
 * for replay attack prevention. This function implements a single retry pattern
 * with configurable delay and jitter to handle these errors gracefully.
 *
 * The retry mechanism:
 * 1. If DPoP is not enabled, executes the function once without retry logic
 * 2. If DPoP is enabled:
 *    - Executes the provided function
 *    - If a DPoP nonce error occurs (400 with use_dpop_nonce error), waits with jitter
 *    - Retries the function once
 *    - The DPoP handle automatically learns and applies the new nonce on retry
 * 3. If the retry fails or any other error occurs, re-throws the error
 *
 * Note: The DPoP handle (oauth4webapi) is stateful and automatically learns nonces
 * from the DPoP-Nonce response header. No manual nonce injection is required.
 *
 * * ## Dual-Path Retry Logic
 *
 * The wrapper supports TWO different error paths, depending on how the caller
 * structures their token request:
 *
 * ### Path 1: HTTP Request Only (Recommended for Auth Code Flow)
 * **When to use:** Wrapping ONLY the HTTP request, not response processing*
 * **Error handling:**
 * - Nonce errors are detected via `response.status === 400` check (line 135)
 * - Non-nonce 400 errors pass through unchanged
 * - No exception is thrown; Response is returned for caller to process
 *
 * ### Path 2: HTTP Request + Response Processing (Used for Refresh/Connection Flows)
 * **When to use:** Wrapping both HTTP request AND response processing
 *
 *  * **Error handling:**
 * - Nonce errors are detected via `isDPoPNonceError(error)` check (line 150)
 * - Non-nonce errors are re-thrown unchanged
 * - Caller receives either a successful response or an exception
 *
 * @template T - The return type of the function being executed
 * @param fn - The async function to execute with retry logic
 * @param config - Configuration object with retry behavior and DPoP enablement flag
 * @param config.isDPoPEnabled - Whether DPoP nonce retry logic should be applied (default: false)
 * @param config.delay - Retry delay in milliseconds (default: 100)
 * @param config.jitter - Whether to apply jitter to retry delay (default: true)
 * @returns The result of the function execution
 * @throws The original error if it's not a DPoP nonce error or if retry fails
 *
 * @example
 * ```typescript
 * import { withDPoPNonceRetry } from "@auth0/nextjs-auth0/server";
 * import * as oauth from "oauth4webapi";
 *
 * const dpopHandle = oauth.DPoP(client, keyPair);
 *
 * const result = await withDPoPNonceRetry(
 *   async () => {
 *     return await authorizationCodeGrantRequest(
 *       metadata,
 *       client,
 *       clientAuth,
 *       params,
 *       redirectUri,
 *       codeVerifier,
 *       { DPoP: dpopHandle }
 *     );
 *   },
 *   { isDPoPEnabled: true, delay: 100, jitter: true }
 * );
 *
 * // The DPoP handle automatically learned the nonce from error response
 * // and injected it on retry
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449#section-7.1 | RFC 9449 Section 7.1: DPoP Nonce}
 */
export async function withDPoPNonceRetry<T>(
  fn: () => Promise<T>,
  config?: RetryConfig & { isDPoPEnabled?: boolean }
): Promise<T> {
  // If DPoP is not enabled, execute without retry logic
  if (!config?.isDPoPEnabled) {
    return await fn();
  }

  /**
   * PATH 1: Response Object Inspection (Auth Code Flow)
   *
   * When fn() returns a Response object (not thrown), we check its status.
   * If 400 with use_dpop_nonce error, extract nonce from error body and retry.
   * This path is used when response processing happens OUTSIDE the wrapper.
   *
   * PATH 2: Exception Handling (Refresh/Connection Flows)
   * When fn() includes response processing that throws, we catch exceptions above.
   * Both paths support automatic nonce retry per RFC 9449 Section 8.
   *
   * @see withDPoPNonceRetry JSDoc for detailed explanation of dual-path retry logic
   */
  try {
    const response = await fn();

    // Check if this is a 400 error response with use_dpop_nonce
    if (response instanceof Response && response.status === 400) {
      try {
        const errorBody = await response.clone().json();
        if (errorBody.error === "use_dpop_nonce") {
          // This is a DPoP nonce error, retry with delay and jitter
          await applyRetryDelay(config);
          // Retry the request - the DPoP handle automatically learned the nonce
          return await fn();
        }
      } catch {
        // If JSON parsing fails, it's not a DPoP nonce error - return original response
      }
    }

    return response;
  } catch (error) {
    if (isDPoPNonceError(error)) {
      // This is a DPoP nonce error, retry with delay and jitter
      await applyRetryDelay(config);
      // Retry the request - the DPoP handle automatically learned the nonce
      return await fn();
    } else {
      throw error;
    }
  }
}
