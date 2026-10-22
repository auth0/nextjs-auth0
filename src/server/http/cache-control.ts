import type { NextResponse } from "next/server.js";

/**
 * Marks a response that writes the session cookie as not cacheable, so no CDN or proxy serves one
 * user's `Set-Cookie` to another. Same headers as nextjs.
 */
export function addCacheControlHeadersForSession(res: NextResponse): void {
  res.headers.set(
    "Cache-Control",
    "private, no-cache, no-store, must-revalidate, max-age=0"
  );
  res.headers.set("Pragma", "no-cache");
  res.headers.set("Expires", "0");
}
