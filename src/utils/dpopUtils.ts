import { generateKeyPair, isDPoPNonceError } from "oauth4webapi";

import { DpopKeyPair, RetryConfig } from "../types/dpop.js";

export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}

/**
 * Executes a function with retry logic for DPoP nonce errors.
 * Implements a single retry with configurable delay and optional jitter.
 *
 * @param fn - The async function to execute
 * @param retryConfig - Configuration for retry behavior
 * @returns The result of the function execution
 * @throws The original error if it's not a DPoP nonce error or if retry fails
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
