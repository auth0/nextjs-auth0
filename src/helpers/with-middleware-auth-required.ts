import { NextMiddleware, NextResponse } from 'next/server';
import { SessionCache } from '../session';

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
  { login, callback }: { login: string; callback: string },
  getSessionCache: () => SessionCache
): WithMiddlewareAuthRequired {
  return function withMiddlewareAuthRequired(middleware?): NextMiddleware {
    return async function wrappedMiddleware(...args) {
      const [req] = args;
      const { pathname, origin, search } = req.nextUrl;
      const ignorePaths = [login, callback, '/_next', '/favicon.ico'];
      if (ignorePaths.some((p) => pathname.startsWith(p))) {
        return;
      }

      const sessionCache = getSessionCache();

      const authRes = NextResponse.next();
      const session = await sessionCache.get(req, authRes);
      if (!session?.user) {
        if (pathname.startsWith('/api')) {
          return NextResponse.json(
            {
              error: 'not_authenticated',
              description: 'The user does not have an active session or is not authenticated'
            },
            { status: 401 }
          );
        }
        return NextResponse.redirect(
          new URL(`${login}?returnTo=${encodeURIComponent(`${pathname}${search}`)}`, origin)
        );
      }
      const res = await (middleware && middleware(...args));

      if (res) {
        const nextRes = new NextResponse(res.body, res);
        let cookies = authRes.cookies.getAll();
        if ('cookies' in res) {
          for (const cookie of res.cookies.getAll()) {
            nextRes.cookies.set(cookie);
          }
        }
        for (const cookie of cookies) {
          if (!nextRes.cookies.get(cookie.name)) {
            nextRes.cookies.set(cookie);
          }
        }
        return nextRes;
      } else {
        return authRes;
      }
    };
  };
}
