import type { NextRequest } from "next/server"
import createMiddleware from "next-intl/middleware"

import { auth0 } from "./lib/auth0"
import { routing } from "./src/i18n/routing"

const intlMiddleware = createMiddleware(routing)

export async function middleware(request: NextRequest) {
  const authResponse = await auth0.middleware(request)

  // if path starts with /auth, let the auth middleware handle it
  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authResponse
  }

  // call any other middleware here
  const intlRes = intlMiddleware(request)

  // Combine headers from authResponse (from auth0.middleware) and intlRes (from intlMiddleware).
  // If authResponse contains 'x-middleware-next' (signaling Next.js to proceed to the page),
  // but intlRes is a response that should terminate the request chain (like a redirect or an error),
  // we must NOT copy 'x-middleware-next' from authResponse. Doing so would override
  // intlRes's decision to stop the request.
  for (const [key, value] of authResponse.headers) {
    if (key.toLowerCase() === 'x-middleware-next') {
      // Check if intlRes is a redirect (3xx status code) or an error (4xx, 5xx status code).
      const isIntlResponseTerminating = intlRes.status >= 300;
      if (isIntlResponseTerminating) {
        // If intlRes is already redirecting or returning an error,
        // do not copy 'x-middleware-next' from authResponse.
        // This allows intlRes's redirect/error to take effect.
        continue;
      }
    }
    // For all other headers, or if 'x-middleware-next' can be safely copied,
    // set them on intlRes. This ensures session cookies from authResponse are preserved.
    intlRes.headers.set(key, value);
  }

  return intlRes
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
}
