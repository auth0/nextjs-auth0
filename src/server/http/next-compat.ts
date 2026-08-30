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
