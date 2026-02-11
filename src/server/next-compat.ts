import type { NextConfig } from "next";
import { NextRequest, NextResponse } from "next/server.js";

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

function tryCloneRequest(input: Request): Request | null {
  if (typeof (input as any).clone !== "function") {
    return null;
  }

  try {
    return input.clone();
  } catch {
    return null;
  }
}

function getSafeBody(input: any): BodyInit | null | undefined {
  if (!("body" in input)) {
    return undefined;
  }

  const body = input.body;

  if (body == null) {
    return body;
  }

  if (input.bodyUsed) {
    return undefined;
  }

  const locked = (body as any).locked;
  if (typeof locked === "boolean" && locked) {
    return undefined;
  }

  return body as BodyInit;
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

  const source =
    input instanceof Request ? (tryCloneRequest(input) ?? input) : input;
  const body = getSafeBody(source);

  const init: any = {
    method: source.method,
    headers: source.headers,
    duplex: (source as any).duplex ?? "half",
    ...(body !== undefined ? { body } : {})
  };

  if (nextConfig) {
    init.nextConfig = nextConfig;
  }

  return new NextRequest(source.url, init);
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
