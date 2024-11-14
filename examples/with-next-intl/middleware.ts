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

  // add any headers from auth to the response
  for (const [key, value] of authResponse.headers) {
    intlRes.headers.set(key, value)
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
