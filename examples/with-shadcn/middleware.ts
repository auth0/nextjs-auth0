import type { NextRequest } from "next/server"

import { auth0 } from "./lib/auth0"

export async function middleware(request: NextRequest) {
  const res =  await auth0.middleware(request);

  const session = await auth0.getSession(request);

  if (session) {
    console.log('There is a session')
    await auth0.getFederatedConnectionAccessToken('google-oauth2');
  } else {
    console.log('There is no session')
    await auth0.getFederatedConnectionAccessToken('google-oauth2');
  }

  return res;
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
