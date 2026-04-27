import { auth0 } from "@/lib/auth0";
import { type NextRequest } from "next/server";

// undici (used for mTLS) requires Node.js built-ins (fs, net, tls) that are
// not available in the Edge runtime. Force the Node.js runtime here.
export const runtime = "nodejs";

export async function middleware(request: NextRequest) {
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
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"
  ]
};
