import type { IncomingMessage } from "http";
import type { NextConfig } from "next";
import { NextRequest, NextResponse } from "next/server.js";
import type { NextApiRequest } from "next/types.js";

function collectFromNextUrl(input: Request): NextConfig | undefined {
  let config: NextConfig | undefined;

  try {
    const nextUrl: any = (input as any).nextUrl;

    // Return early if nextUrl is not accessible
    if (!nextUrl) {
      return undefined;
    }

    // Handle basePath config
    if (typeof nextUrl.basePath === "string" && nextUrl.basePath) {
      config = { basePath: nextUrl.basePath };
    }

    // Handle i18n config
    if (
      typeof nextUrl.locale === "string" ||
      typeof nextUrl.defaultLocale === "string"
    ) {
      config = {
        ...(config || {}),
        i18n: {
          locales: nextUrl.locale ? [nextUrl.locale] : [],
          defaultLocale: nextUrl.defaultLocale
        }
      };
    }

    // Handle trailingSlash config
    if (typeof nextUrl.trailingSlash === "boolean") {
      config = { ...(config || {}), trailingSlash: nextUrl.trailingSlash };
    }
  } catch {
    // ignore inaccessible nextUrl
  }

  return config && Object.keys(config).length ? config : undefined;
}

/**
 * Normalize a Request or NextRequest to a NextRequest instance.
 * Ensures consistent behavior across Next.js 15 (Edge) and 16 (Node Proxy).
 * @internal
 */
export function toNextRequest(input: Request | NextRequest): NextRequest {
  if (input instanceof NextRequest) {
    return input;
  }

  const nextConfig = collectFromNextUrl(input);

  const init: any = {
    method: input.method,
    headers: input.headers,
    body: input.body as any,
    duplex: (input as any).duplex ?? "half"
  };

  if (nextConfig) {
    init.nextConfig = nextConfig;
  }

  return new NextRequest(input.url, init);
}

/**
 * Normalize a Response or NextResponse to a NextResponse instance.
 * Converts plain Fetch Response objects into NextResponse while preserving
 * headers, body, status, and statusText.
 *
 * Required for environments where plain Responses lack Next.js cookie helpers.
 * @internal
 */
export function toNextResponse(res: Response | NextResponse): NextResponse {
  if (res instanceof NextResponse) {
    return res;
  }

  const headers = new Headers(res.headers);

  const nextRes = new NextResponse(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers
  });

  try {
    if ("url" in res && res.url) {
      (nextRes as any).url = res.url;
    }
  } catch {
    // ignore if url isn't accessible
  }

  return nextRes;
}

type PagesRouterLikeRequest = IncomingMessage | NextApiRequest;

/**
 * Convert IncomingMessage/NextApiRequest headers to a web-standard Headers object.
 * @internal
 */
export function toHeadersFromIncomingMessage(
  req: PagesRouterLikeRequest
): Headers {
  const headers = new Headers();
  for (const key in req.headers) {
    const value = req.headers[key];
    if (Array.isArray(value)) {
      for (const v of value) {
        headers.append(key, v);
      }
    } else if (value !== undefined) {
      headers.append(key, value);
    }
  }
  return headers;
}

/**
 * Construct a URL from a Pages Router request (IncomingMessage).
 * Uses the Host header and x-forwarded-proto to build a full URL.
 * Returns undefined if Host header is missing or URL construction fails.
 * @internal
 */
export function toUrlFromPagesRouter(
  req: PagesRouterLikeRequest
): URL | undefined {
  try {
    const host = Array.isArray(req.headers.host)
      ? req.headers.host[0]
      : req.headers.host;
    if (!host) return undefined;
    const proto = Array.isArray(req.headers["x-forwarded-proto"])
      ? req.headers["x-forwarded-proto"][0]
      : (req.headers["x-forwarded-proto"] as string);
    return new URL(req.url ?? "/", `${proto || "https"}://${host}`);
  } catch {
    return undefined;
  }
}

/**
 * Re-serialize an already-parsed Pages Router request body back into a string.
 *
 * Next.js' API route body parser populates `req.body` with an already-parsed
 * value (an object for JSON / urlencoded payloads, a string for text). To run
 * the existing `NextRequest`-based auth handlers we must reconstruct a body that
 * those handlers can read back the same way. We re-serialize based on the
 * original `content-type` so that, for example, the back-channel logout handler
 * (which reads `application/x-www-form-urlencoded` via `req.text()` +
 * `URLSearchParams`) still sees a urlencoded body rather than JSON.
 */
function serializePagesRouterBody(
  body: unknown,
  contentType: string
): string | undefined {
  if (body === undefined || body === null) {
    return undefined;
  }

  // Already a string (text/* payloads, or bodies Next.js left unparsed).
  if (typeof body === "string") {
    return body;
  }

  // application/x-www-form-urlencoded → re-encode the parsed object.
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return new URLSearchParams(body as Record<string, string>).toString();
  }

  // Default to JSON for parsed objects (the common case for API routes).
  return JSON.stringify(body);
}

/**
 * Normalize a Pages Router request (`NextApiRequest`) into a `NextRequest`.
 *
 * This allows the SDK's existing `NextRequest`-based auth handlers to run
 * unchanged when auth routes are mounted as Pages Router API routes
 * (`pages/api/auth/[...auth0].ts`) instead of in the middleware.
 * @internal
 */
export function toNextRequestFromPagesRouter(req: NextApiRequest): NextRequest {
  const url =
    toUrlFromPagesRouter(req) ??
    new URL(req.url ?? "/", process.env.APP_BASE_URL);

  const headers = toHeadersFromIncomingMessage(req);

  const method = (req.method ?? "GET").toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";

  const body = hasBody
    ? serializePagesRouterBody(req.body, headers.get("content-type") ?? "")
    : undefined;

  // The re-serialized body length may differ from the original raw payload, so
  // drop length/encoding headers and let the runtime recompute them.
  headers.delete("content-length");
  headers.delete("transfer-encoding");

  const init: any = {
    method,
    headers,
    duplex: "half"
  };

  if (body !== undefined) {
    init.body = body;
  }

  return new NextRequest(url, init);
}
