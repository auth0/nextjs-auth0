import { NextMiddleware, NextResponse } from 'next/server';
import { MiddlewareSessionCache } from '../session';

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
  getSessionCache: () => MiddlewareSessionCache
): WithMiddlewareAuthRequired {
  return function withMiddlewareAuthRequired(middleware?): NextMiddleware {
    return async function wrappedMiddleware(...args) {
      const [req] = args;
      const { pathname, origin } = req.nextUrl;
      const ignorePaths = [login, callback, '/_next', '/favicon.ico'];
      if (ignorePaths.some((p) => pathname.startsWith(p))) {
        console.log('ignoring', pathname);
        return;
      }

      const sessionCache = getSessionCache();

      await sessionCache.init(req);
      const session = sessionCache.get(req);
      if (!session?.user) {
        console.log('redirecting to', login, 'from', pathname);
        return NextResponse.redirect(new URL(login, origin));
      }
      console.log('Running mw for', pathname);
      const res = await ((middleware && middleware(...args)) || NextResponse.next());
      await sessionCache.save(req, res as NextResponse);
      return res;
    };
  };
}
