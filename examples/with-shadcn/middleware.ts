import { NextResponse, type NextRequest } from "next/server";

import { auth0 } from "./lib/auth0";

export async function middleware(request: NextRequest) {
  // Protecting all routes that start with /test
  if (request.nextUrl.pathname.startsWith("/test")) {
    const session = await auth0.getSession(request);

    if (!session) {
      // user is not authenticated, redirect to login page
      return NextResponse.redirect(
        new URL("/auth/login", request.nextUrl.origin)
      );
    }
  }
  return await auth0.middleware(request);
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
