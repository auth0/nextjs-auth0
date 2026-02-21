/**
 * Utility to extract OAuth error details from oauth4webapi errors.
 *
 * oauth4webapi's `parseOAuthResponseErrorBody()` only parses error bodies for
 * HTTP 4xx responses (producing `ResponseBodyError` with `.error` and
 * `.error_description`). For 5xx responses (e.g., when Auth0 Actions use
 * `api.access.deny()`), it throws `OperationProcessingError` with the raw
 * `Response` as `.cause`, losing the structured error information.
 *
 * This helper recovers those details by checking:
 * 1. If the error already has `.error` (ResponseBodyError from 4xx) → use directly
 * 2. If `.cause` is a `Response` (OperationProcessingError from 5xx) → parse JSON body
 * 3. Otherwise → return empty object
 *
 * See: https://github.com/auth0/nextjs-auth0/issues/2512
 */

export interface OAuthErrorDetails {
  error?: string;
  error_description?: string;
}

/**
 * Extract `error` and `error_description` from an oauth4webapi error,
 * handling both 4xx `ResponseBodyError` and 5xx `OperationProcessingError`.
 */
export async function extractOAuthErrorDetails(
  err: unknown
): Promise<OAuthErrorDetails> {
  if (!err || typeof err !== "object") {
    return {};
  }

  const e = err as Record<string, unknown>;

  // Case 1: ResponseBodyError (4xx) — error/error_description are direct properties
  if (typeof e.error === "string") {
    return {
      error: e.error,
      error_description:
        typeof e.error_description === "string"
          ? e.error_description
          : undefined
    };
  }

  // Case 2: OperationProcessingError (5xx) — cause is the raw Response object
  if (e.cause instanceof Response) {
    try {
      const body = await e.cause.clone().json();
      if (body && typeof body === "object") {
        return {
          error: typeof body.error === "string" ? body.error : undefined,
          error_description:
            typeof body.error_description === "string"
              ? body.error_description
              : undefined
        };
      }
    } catch {
      // Response body wasn't JSON — nothing to extract
    }
  }

  return {};
}
