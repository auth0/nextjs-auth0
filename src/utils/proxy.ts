import { NextRequest } from "next/server.js";

import { ProxyOptions } from "../types/index.js";

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
  "x-real-ip",

  // CORS REQUEST HEADERS
  // Without these headers, Preflight fails, browser blocks all cross-origin requests
  // See: RFC 7231 §4.3.1 (preflight semantics), RFC 6454 (origin), WHATWG Fetch Spec
  "origin",
  "access-control-request-method",
  "access-control-request-headers"
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
 * 2. Strips all hop-by-hop headers as defined by https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1.
 *
 * @param request The incoming NextRequest object.
 * @returns A WHATWG Headers object suitable for `fetch`.
 */
export function buildForwardedRequestHeaders(request: NextRequest): Headers {
  const forwardedHeaders = new Headers();

  request.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();

    // Forward if:
    // 1. It's in the allow-list, AND
    // 2. It's not a hop-by-hop header
    const shouldForward =
      DEFAULT_HEADER_ALLOW_LIST.has(lowerKey) &&
      !HOP_BY_HOP_HEADERS.has(lowerKey);

    if (shouldForward) {
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

/**
 * Builds a URL representing the upstream target for a proxied request.
 *
 * This function correctly handles the path transformation by:
 * 1. Extracting the path segment that comes AFTER the proxyPath
 * 2. Intelligently combining it with targetBaseUrl to avoid path segment duplication
 *
 * Example:
 *   - proxyPath: "/me"
 *   - targetBaseUrl: "https://issuer/me/v1"
 *   - incoming: "/me/v1/some-endpoint"
 *   - remaining path: "/v1/some-endpoint" (after removing "/me")
 *   - result: "https://issuer/me/v1/some-endpoint" (no /v1 duplication)
 *
 * @param req - The incoming request to mirror when constructing the target URL.
 * @param options - Proxy configuration containing the base URL and proxy path.
 * @returns A URL object pointing to the resolved target endpoint with forwarded query parameters.
 */
export function transformTargetUrl(
  req: NextRequest,
  options: ProxyOptions
): URL {
  const targetBaseUrl = options.targetBaseUrl;

  // Extract the path segment that comes AFTER the proxyPath
  // If proxyPath is "/me" and pathname is "/me/v1/some-endpoint",
  // the remaining path is "/v1/some-endpoint"
  let remainingPath = req.nextUrl.pathname.startsWith(options.proxyPath)
    ? req.nextUrl.pathname.slice(options.proxyPath.length)
    : req.nextUrl.pathname;

  // Ensure proper path joining by handling the slash
  // If remainingPath is empty or doesn't start with /, handle accordingly
  if (remainingPath && !remainingPath.startsWith("/")) {
    remainingPath = "/" + remainingPath;
  }

  // Remove trailing slash from targetBaseUrl for consistent joining
  const baseUrlTrimmed = targetBaseUrl.replace(/\/$/, "");

  // Parse the targetBaseUrl to extract its path
  const baseUrl = new URL(baseUrlTrimmed);
  const basePath = baseUrl.pathname;

  // Check if remainingPath starts with a segment that's already at the end of basePath
  // to avoid duplication (e.g., basePath="/me/v1" + remainingPath="/v1/x" → "/me/v1/x")
  let finalPath = basePath;

  if (remainingPath && remainingPath !== "/") {
    // Split paths into segments for comparison
    const baseSegments = basePath.split("/").filter(Boolean);
    const remainingSegments = remainingPath.split("/").filter(Boolean);

    // Find the longest overlap by checking from longest to shortest
    // Break on first match
    let overlapLength = 0;
    const maxOverlap = Math.min(baseSegments.length, remainingSegments.length);

    for (let i = maxOverlap; i >= 1; i--) {
      const baseEnd = baseSegments.slice(-i);
      const remainingStart = remainingSegments.slice(0, i);

      if (baseEnd.every((seg, idx) => seg === remainingStart[idx])) {
        overlapLength = i;
        break; // Found longest match, stop searching
      }
    }

    // Build final path by appending non-overlapping segments
    const nonOverlappingSegments = remainingSegments.slice(overlapLength);
    if (nonOverlappingSegments.length > 0) {
      const separator = basePath === "/" || basePath.endsWith("/") ? "" : "/";
      finalPath = basePath + separator + nonOverlappingSegments.join("/");
    }
  }

  // Build the final URL with the de-duplicated path
  const targetUrl = new URL(baseUrl.origin + finalPath);

  req.nextUrl.searchParams.forEach((value, key) => {
    targetUrl.searchParams.set(key, value);
  });

  return targetUrl;
}
