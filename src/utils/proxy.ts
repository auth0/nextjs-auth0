import { NextRequest } from "next/server.js";

/**
 * A default allow-list of headers to forward.
 */
const DEFAULT_HEADER_ALLOW_LIST: Set<string> = new Set([
  // Common End-to-End Headers
  "accept",
  "accept-language",
  "content-language",
  "content-type",
  "user-agent",

  // Caching & Conditional Requests
  "cache-control",
  "if-match",
  "if-none-match",
  "if-modified-since",
  "if-unmodified-since",
  "etag",

  // Tracing & Observability
  "x-request-id",
  "x-correlation-id",
  "traceparent",
  "tracestate",

  // PROXY HEADERS (for IP & Rate Limiting)
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip"
]);

/**
 * Hop-by-hop headers that MUST be removed.
 * These are relevant only for a single transport link (client <-> proxy).
 * @see https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1
 */
const HOP_BY_HOP_HEADERS: Set<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

/**
 * Securely builds a Headers object for forwarding a NextRequest via fetch.
 *
 * This function:
 * 1. Uses a strict **allow-list** (DEFAULT_HEADER_ALLOW_LIST).
 * 2. Allows adding app-specific headers (e.g., 'authorization').
 * 3. Strips all hop-by-hop headers as defined by https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1.
 *
 * @param request The incoming NextRequest object.
 * @param options Configuration for additional headers.
 * @returns A WHATWG Headers object suitable for `fetch`.
 */
export function buildForwardedRequestHeaders(request: NextRequest): Headers {
  const forwardedHeaders = new Headers();

  request.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();

    // Only forward if it's in the allow-list AND not a hop-by-hop header
    if (
      DEFAULT_HEADER_ALLOW_LIST.has(lowerKey) &&
      !HOP_BY_HOP_HEADERS.has(lowerKey)
    ) {
      forwardedHeaders.set(key, value);
    }
  });

  return forwardedHeaders;
}

/**
 * Securely builds a Headers object for forwarding a fetch response.
 *
 * This function:
 * 1. Strips all hop-by-hop headers as defined by https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1.
 *
 * @param request The incoming Response object.
 * @returns A WHATWG Headers object suitable for `fetch`.
 */
export function buildForwardedResponseHeaders(response: Response): Headers {
  const forwardedHeaders = new Headers();

  response.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();

    // Only forward if it's not a hop-by-hop header
    if (!HOP_BY_HOP_HEADERS.has(lowerKey)) {
      forwardedHeaders.set(key, value);
    }
  });

  return forwardedHeaders;
}
