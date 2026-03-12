/**
 * Interface for extracted OAuth2 error details
 */
export interface OAuth2ErrorBody {
  error: string | undefined;
  error_description: string | undefined;
}

/**
 * Extract OAuth2 error details from oauth4webapi errors.
 *
 * Handles both:
 * - 4xx ResponseBodyError (direct .error and .error_description properties)
 * - 5xx OperationProcessingError (Response object in .cause)
 *
 * Priority: Direct properties (4xx) > Response body parsing (5xx) > fallback
 *
 * @param error - Error object from oauth4webapi or unknown error
 * @returns Promise with extracted { error, error_description } or { error: undefined, error_description: undefined }
 */
export async function getOAuth2ErrorDetails(
  error: unknown
): Promise<OAuth2ErrorBody> {
  // Step 1: Input validation
  if (!error || typeof error !== "object") {
    return { error: undefined, error_description: undefined };
  }

  const err = error as Record<string, unknown>;

  // Step 2: Priority path (4xx - direct properties)
  // If error has .error as string property, use it directly (no async work)
  if (typeof err.error === "string") {
    return {
      error: err.error,
      error_description:
        typeof err.error_description === "string"
          ? err.error_description
          : undefined
    };
  }

  // Step 3: 5xx path (Response object in .cause)
  // If error.cause is a Response object, try to parse its body
  if (err.cause instanceof Response) {
    try {
      // Clone the Response to avoid "body already consumed" errors
      const responseClone = err.cause.clone();

      // Attempt to parse JSON body
      const body = await responseClone.json();

      // Extract error fields if present
      if (typeof body === "object" && body !== null) {
        return {
          error: typeof body.error === "string" ? body.error : undefined,
          error_description:
            typeof body.error_description === "string"
              ? body.error_description
              : undefined
        };
      }
    } catch {
      // Silently fall through if clone, json parse, or any other error occurs
      // Response might have no body, invalid JSON, read failure, etc.
    }
  }

  // Step 4: Fallback (no error details available)
  return { error: undefined, error_description: undefined };
}
