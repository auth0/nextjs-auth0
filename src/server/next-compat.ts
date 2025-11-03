import { NextRequest, NextResponse } from "next/server.js";

/**
 * Normalize a Request or NextRequest to a NextRequest instance.
 * Ensures consistent behavior across Next.js 15 (Edge) and 16 (Node Proxy).
 * @internal
 */
export function toNextRequest(input: Request | NextRequest): NextRequest {
  if (input instanceof NextRequest) {
    return input;
  }

  return new NextRequest(input.url, {
    method: input.method,
    headers: input.headers,
    body: input.body as any,
    duplex: (input as any).duplex ?? "half"
  });
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
