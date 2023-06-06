import { NextApiResponse, NextApiRequest, NextApiHandler } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { get, SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

export type AppRouteHandlerFnContext = {
  params?: Record<string, string | string[]>;
};

/**
 * Handler function for app routes.
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
) => Promise<NextResponse> | NextResponse;

/**
 * Wrap an API route to check that the user has a valid session. If they're not logged in the
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
export type WithApiAuthRequiredAppRoute = (apiRoute: AppRouteHandlerFn) => AppRouteHandlerFn;
export type WithApiAuthRequiredPageRoute = (apiRoute: NextApiHandler) => NextApiHandler;
export type WithApiAuthRequired = WithApiAuthRequiredAppRoute & WithApiAuthRequiredPageRoute;

/**
 * @ignore
 */
export default function withApiAuthFactory(sessionCache: SessionCache): WithApiAuthRequired {
  const pageRouteHandler = pageRouteHandlerFactory(sessionCache);
  const appRouteHandler = appRouteHandlerFactory(sessionCache);

  return (apiRoute: AppRouteHandlerFn | NextApiHandler): any =>
    (req: NextRequest | NextApiRequest, resOrParams: AppRouteHandlerFnContext | NextApiResponse) => {
      if (req instanceof Request) {
        return appRouteHandler(apiRoute as AppRouteHandlerFn)(req, resOrParams as AppRouteHandlerFnContext);
      }
      return (pageRouteHandler as WithApiAuthRequiredPageRoute)(apiRoute as NextApiHandler)(
        req as NextApiRequest,
        resOrParams as NextApiResponse
      );
    };
}

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
      nextApiRes.cookies.set(cookie);
    }
    return nextApiRes;
  };

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
