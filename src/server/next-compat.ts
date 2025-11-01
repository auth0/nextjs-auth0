import { NextRequest, NextResponse } from "next/server.js";

export function toNextRequest(input: Request | NextRequest): NextRequest {
  if (input instanceof NextRequest) {
    return input;
  }

  // 16 proxy.ts → plain Request
  return new NextRequest(input.url, {
    method: input.method,
    headers: input.headers,
    body: input.body as any,
    duplex: (input as any).duplex ?? "half"
  });
}

export function isPrefetch(req: Request | NextRequest): boolean {
  const h = req.headers;
  if (h.get("x-middleware-prefetch") === "1") return true;
  if (h.get("next-router-prefetch") === "1") return true;
  if (h.get("purpose") === "prefetch") return true;
  return false;
}
