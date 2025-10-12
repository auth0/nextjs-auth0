import { allowInsecureRequests, customFetch, DPoPHandle, generateKeyPair, HttpRequestOptions, isDPoPNonceError, protectedResourceRequest, ProtectedResourceRequestBody } from "oauth4webapi";

import { DpopKeyPair } from "../types/dpop.js";

export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}

/**
 * Executes a function with retry logic for DPoP nonce errors.
 * Implements a small delay (100ms) before retrying to avoid rapid successive requests.
 *
 * @param fn - The async function to execute
 * @returns The result of the function execution
 * @throws The original error if it's not a DPoP nonce error or if retry fails
 */
export async function withDPoPNonceRetry<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e: any) {
    if (isDPoPNonceError(e)) {
      // Small delay before retry to avoid rapid successive requests
      await new Promise((resolve) => setTimeout(resolve, 100));
      // The RS-signalled nonce is now cached, retrying
      return await fn();
    }
    throw e;
  }
}p