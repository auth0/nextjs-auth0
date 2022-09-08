import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { SessionCache } from '../session';

/**
 * Middleware
 * @category Server
 */
export type WithMiddlewareAuthRequired = (middleware?: NextMiddleware) => NextMiddleware;

/**
 * @ignore
 */
export default function withMiddlewareAuthRequiredFactory(
  { login, callback }: { login: string; callback: string },
  getSessionCache: () => SessionCache<NextRequest, NextResponse>
): WithMiddlewareAuthRequired {
  return function withMiddlewareAuthRequired(middleware?): NextMiddleware {
    return async function wrappedMiddleware(...args) {
      const [req] = args;
      const { pathname, origin } = req.nextUrl;
      const ignorePaths = [login, callback, '/_next', '/favicon.ico'];
      if (ignorePaths.some((p) => pathname.startsWith(p))) {
        return;
      }

      const sessionCache = getSessionCache();

      const authRes = NextResponse.next();
      const session = await sessionCache.get(req, authRes);
      if (!session?.user) {
        return NextResponse.redirect(
          new URL(`${login}?returnTo=${encodeURIComponent(req.nextUrl.toString())}`, origin)
        );
      }
      const res = await (middleware && middleware(...args));

      if (res) {
        const headers = new Headers(res.headers);
        const cookies = headers.get('set-cookie')?.split(', ') || [];
        const authCookies = authRes.headers.get('set-cookie')?.split(', ') || [];
        if (cookies.length || authCookies.length) {
          headers.set('set-cookie', [...authCookies, ...cookies].join(', '));
        }
        return NextResponse.next({ ...res, headers });
      } else {
        return authRes;
      }
    };
  };
}
