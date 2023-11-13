import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { SessionCache } from '../session';
import { GetConfig } from '../config';
import { Auth0NextRequest } from '../http';

/**
 * Pass custom options to {@link WithMiddlewareAuthRequired}.
 *
 * @category Server
 */
export type WithMiddlewareAuthRequiredOptions = {
  middleware?: NextMiddleware;
  returnTo?: string | ((req: NextRequest) => Promise<string> | string);
};

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
 * To provide a custom `returnTo` url to login:
 *
 * ```js
 * // middleware.js
 * import { withMiddlewareAuthRequired, getSession } from '@auth0/nextjs-auth0/edge';
 *
 * export default withMiddlewareAuthRequired({
 *   returnTo: '/foo',
 *   // Custom middleware is provided with the `middleware` config option
 *   async middleware(req) { return NextResponse.next(); }
 * });
 * ```
 *
 * You can also provide a method for `returnTo` that takes the req as an argument.
 *
 * ```js
 * // middleware.js
 * import { withMiddlewareAuthRequired, getSession } from '@auth0/nextjs-auth0/edge';
 *
 * export default withMiddlewareAuthRequired({
 *   returnTo(req) { return `${req.nextURL.basePath}${req.nextURL.pathname}`};
 * });
 * ```
 *
 * @category Server
 */
export type WithMiddlewareAuthRequired = (
  middlewareOrOpts?: NextMiddleware | WithMiddlewareAuthRequiredOptions
) => NextMiddleware;

/**
 * @ignore
 */
export default function withMiddlewareAuthRequiredFactory(
  getConfig: GetConfig,
  sessionCache: SessionCache
): WithMiddlewareAuthRequired {
  return function withMiddlewareAuthRequired(opts?): NextMiddleware {
    return async function wrappedMiddleware(...args) {
      const [req] = args;
      const {
        routes: { login, callback }
      } = await getConfig(new Auth0NextRequest(req));
      let middleware: NextMiddleware | undefined;
      const { pathname, origin, search } = req.nextUrl;
      let returnTo = `${pathname}${search}`;
      if (typeof opts === 'function') {
        middleware = opts;
      } else if (opts) {
        middleware = opts.middleware;
        returnTo = (typeof opts.returnTo === 'function' ? await opts.returnTo(req) : opts.returnTo) || returnTo;
      }
      const ignorePaths = [login, callback, '/_next', '/favicon.ico'];
      if (ignorePaths.some((p) => pathname.startsWith(p))) {
        return;
      }

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
        return NextResponse.redirect(new URL(`${login}?returnTo=${encodeURIComponent(returnTo)}`, origin));
      }
      const res = await (middleware && middleware(...args));

      if (res) {
        const nextRes = new NextResponse(res.body, res);
        const cookies = authRes.cookies.getAll();
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
