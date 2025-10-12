import { generateKeyPair, isDPoPNonceError } from "oauth4webapi";

import { DpopKeyPair, RetryConfig } from "../types/dpop.js";

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
 *   useDpop: true,
 *   dpopKeyPair: keyPair
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
 */
export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}

/**
 * Executes a function with retry logic for DPoP nonce errors.
 *
 * DPoP nonce errors occur when the authorization server requires a fresh nonce
 * for replay attack prevention. This function implements a single retry pattern
 * with configurable delay and jitter to handle these errors gracefully.
 *
 * The retry mechanism:
 * 1. Executes the provided function
 * 2. If a DPoP nonce error occurs, waits for the configured delay
 * 3. Retries the function once with the cached nonce from the error response
 * 4. If the retry fails or any other error occurs, re-throws the error
 *
 * @template T - The return type of the function being executed
 * @param fn - The async function to execute with retry logic
 * @param retryConfig - Configuration for retry behavior (delay and jitter)
 * @returns The result of the function execution
 * @throws The original error if it's not a DPoP nonce error or if retry fails
 *
 * @example
 * ```typescript
 * import { withDPoPNonceRetry } from "@auth0/nextjs-auth0/server";
 *
 * const result = await withDPoPNonceRetry(async () => {
 *   return await protectedResourceRequest(
 *     accessToken,
 *     "GET",
 *     new URL("https://api.example.com/data"),
 *     headers,
 *     null,
 *     { DPoP: dpopHandle }
 *   );
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449#section-7.1 | RFC 9449 Section 7.1: DPoP Nonce}
 */
export async function withDPoPNonceRetry<T>(
  fn: () => Promise<T>,
  retryConfig?: RetryConfig
): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    if (isDPoPNonceError(error)) {
      // Use provided config or defaults
      const delay = retryConfig?.delay ?? 100;
      const jitter = retryConfig?.jitter ?? true;

      let actualDelay = delay;

      // Apply jitter if enabled (adds randomness to prevent thundering herd)
      if (jitter) {
        actualDelay = delay * (0.5 + Math.random() * 0.5); // 50-100% of original delay
      }

      // Delay before retry to avoid rapid successive requests
      await new Promise((resolve) => setTimeout(resolve, actualDelay));

      // The RS-signalled nonce is now cached, retrying
      return await fn();
    }
    throw error;
  }
}
