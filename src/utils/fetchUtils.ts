/**
 * Creates a fetch wrapper that enforces a maximum response body size.
 *
 * Guards against memory exhaustion from oversized OIDC discovery documents,
 * JWKS responses, token endpoint payloads, or other HTTP responses.
 *
 * Two-layer protection:
 * 1. Fast path: rejects immediately if Content-Length header exceeds the limit
 * 2. Streaming guard: wraps the response body to enforce the limit during
 *    chunked transfer-encoding where Content-Length is absent
 *
 * @param baseFetch - The underlying fetch implementation to wrap
 * @param maxBodySize - Maximum allowed response body size in bytes
 * @returns A fetch function that enforces the size limit
 *
 * @internal
 */
export function createSizeLimitedFetch(
  baseFetch: typeof fetch,
  maxBodySize: number
): typeof fetch {
  return async (input, init) => {
    const response = await baseFetch(input, init);

    // Fast path: reject if Content-Length is declared and exceeds limit
    const contentLength = response.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > maxBodySize) {
      // Cancel the response body to release the connection
      await response.body?.cancel();
      throw new Error(
        `Response body too large: ${contentLength} bytes exceeds ${maxBodySize} byte limit`
      );
    }

    // Wrap response body to enforce size limit during streaming consumption
    // (handles chunked transfer-encoding where Content-Length is absent)
    if (response.body) {
      const reader = response.body.getReader();
      let totalBytes = 0;
      const stream = new ReadableStream({
        async pull(controller) {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            return;
          }
          totalBytes += value.byteLength;
          if (totalBytes > maxBodySize) {
            controller.error(
              new Error(
                `Response body too large: exceeded ${maxBodySize} byte limit`
              )
            );
            reader.cancel();
            return;
          }
          controller.enqueue(value);
        }
      });

      return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });
    }

    return response;
  };
}
