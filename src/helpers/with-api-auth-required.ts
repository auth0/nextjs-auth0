import { NextApiResponse, NextApiRequest, NextApiHandler } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { get, SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';
import { isRequest } from '../utils/req-helpers';

/**
 * This contains `param`s, which is an object containing the dynamic route parameters for the current route.
 *
 * See https://nextjs.org/docs/app/api-reference/file-conventions/route#context-optional
 *
 * @category Server
 */
export type AppRouteHandlerFnContext = {
  params?: Record<string, string | string[]>;
};

/**
 * Handler function for app directory api routes.
 *
 * See: https://nextjs.org/docs/app/api-reference/file-conventions/route
 *
 * @category Server
 */
export type AppRouteHandlerFn = (
  /**
   * Incoming request object.
   */
  req: NextRequest,
  /**
   * Context properties on the request (including the parameters if this was a
   * dynamic route).
   */
  ctx: AppRouteHandlerFnContext
) => Promise<Response> | Response;

/**
 * Wrap an app router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // app/protected-api/route.js
 * import { withApiAuthRequired, getSession } from '@auth0/nextjs-auth0';
 *
 * export default withApiAuthRequired(function Protected(req) {
 *   const session = getSession();
 *   ...
 * });
 * ```
 *
 * If you visit `/protected-api` without a valid session cookie, you will get a 401 response.
 *
 * @category Server
 */
export type WithApiAuthRequiredAppRoute = (apiRoute: AppRouteHandlerFn) => AppRouteHandlerFn;

/**
 * Wrap a page router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // pages/api/protected-route.js
 * import { withApiAuthRequired, getSession } from '@auth0/nextjs-auth0';
 *
 * export default withApiAuthRequired(function ProtectedRoute(req, res) {
 *   const session = getSession(req, res);
 *   ...
 * });
 * ```
 *
 * If you visit `/api/protected-route` without a valid session cookie, you will get a 401 response.
 *
 * @category Server
 */
export type WithApiAuthRequiredPageRoute = (apiRoute: NextApiHandler) => NextApiHandler;

/**
 * Protects API routes for Page router pages {@link WithApiAuthRequiredPageRoute} or
 * App router pages {@link WithApiAuthRequiredAppRoute}
 *
 * @category Server
 */
export type WithApiAuthRequired = WithApiAuthRequiredAppRoute & WithApiAuthRequiredPageRoute;

/**
 * @ignore
 */
export default function withApiAuthFactory(sessionCache: SessionCache): WithApiAuthRequired {
  const pageRouteHandler = pageRouteHandlerFactory(sessionCache);
  const appRouteHandler = appRouteHandlerFactory(sessionCache);

  return (apiRoute: AppRouteHandlerFn | NextApiHandler): any =>
    (req: NextRequest | NextApiRequest, resOrParams: AppRouteHandlerFnContext | NextApiResponse) => {
      if (isRequest(req)) {
        return appRouteHandler(apiRoute as AppRouteHandlerFn)(
          req as NextRequest,
          resOrParams as AppRouteHandlerFnContext
        );
      }
      return (pageRouteHandler as WithApiAuthRequiredPageRoute)(apiRoute as NextApiHandler)(
        req as NextApiRequest,
        resOrParams as NextApiResponse
      );
    };
}

/**
 * @ignore
 */
const appRouteHandlerFactory =
  (sessionCache: SessionCache): WithApiAuthRequiredAppRoute =>
  (apiRoute) =>
  async (req, params): Promise<NextResponse> => {
    const res = new NextResponse();
    const [session] = await get({ sessionCache, req, res });
    if (!session || !session.user) {
      return NextResponse.json(
        { error: 'not_authenticated', description: 'The user does not have an active session or is not authenticated' },
        { status: 401 }
      );
    }
    const apiRes: NextResponse | Response = await apiRoute(req, params);
    const nextApiRes: NextResponse = apiRes instanceof NextResponse ? apiRes : new NextResponse(apiRes.body, apiRes);
    for (const cookie of res.cookies.getAll()) {
      if (!nextApiRes.cookies.get(cookie.name)) {
        nextApiRes.cookies.set(cookie);
      }
    }
    return nextApiRes;
  };

/**
 * @ignore
 */
const pageRouteHandlerFactory =
  (sessionCache: SessionCache): WithApiAuthRequiredPageRoute =>
  (apiRoute) =>
  async (req, res) => {
    assertReqRes(req, res);

    const session = await sessionCache.get(req, res);
    if (!session || !session.user) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    await apiRoute(req, res);
  };
