import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { SessionCache } from '../session';
import { splitCookiesString } from '../utils/middleware-cookies';

/**
 * Protect your pages with Next.js Middleware. For example:
 *
 * To protect all your routes:
 *
 * ```js
 * // middleware.js
 * import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/edge';
 *
 * export default withMiddlewareAuthRequired();
 * ```
 *
 * To protect specific routes:
 *
 * ```js
 * // middleware.js
 * import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/edge';
 *
 * export default withMiddlewareAuthRequired();
 *
 * export const config = {
 *   matcher: '/about/:path*',
 * };
 * ```
 * For more info see: https://nextjs.org/docs/advanced-features/middleware#matching-paths
 *
 * To run custom middleware for authenticated users:
 *
 * ```js
 * // middleware.js
 * import { withMiddlewareAuthRequired, getSession } from '@auth0/nextjs-auth0/edge';
 *
 * export default withMiddlewareAuthRequired(async function middleware(req) {
 *   const res = NextResponse.next();
 *   const user = await getSession(req, res);
 *   res.cookies.set('hl', user.language);
 *   return res;
 * });
 * ```
 *
 * @category Server
 */
export type WithMiddlewareAuthRequired = (middleware?: NextMiddleware) => NextMiddleware;

/**
 * @ignore
 */
export default function withMiddlewareAuthRequiredFactory(
  { login, callback, unauthorized }: { login: string; callback: string; unauthorized: string },
  getSessionCache: () => SessionCache<NextRequest, NextResponse>
): WithMiddlewareAuthRequired {
  return function withMiddlewareAuthRequired(middleware?): NextMiddleware {
    return async function wrappedMiddleware(...args) {
      const [req] = args;
      const { pathname, origin, search } = req.nextUrl;
      const ignorePaths = [login, callback, unauthorized, '/_next', '/favicon.ico'];
      if (ignorePaths.some((p) => pathname.startsWith(p))) {
        return;
      }

      const sessionCache = getSessionCache();

      const authRes = NextResponse.next();
      const session = await sessionCache.get(req, authRes);
      if (!session?.user) {
        if (pathname.startsWith('/api')) {
          return NextResponse.rewrite(new URL(unauthorized, origin), { status: 401 });
        }
        return NextResponse.redirect(
          new URL(`${login}?returnTo=${encodeURIComponent(`${pathname}${search}`)}`, origin)
        );
      }
      const res = await (middleware && middleware(...args));

      if (res) {
        const headers = new Headers(res.headers);
        const authCookies = splitCookiesString(authRes.headers.get('set-cookie')!);
        if (authCookies.length) {
          for (const cookie of authCookies) {
            headers.append('set-cookie', cookie);
          }
        }
        return NextResponse.next({ ...res, status: res.status, headers });
      } else {
        return authRes;
      }
    };
  };
}
