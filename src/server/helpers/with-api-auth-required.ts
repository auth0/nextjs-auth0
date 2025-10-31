import { NextApiHandler } from "next";
import { NextRequest, NextResponse } from "next/server.js";

import { Auth0Client } from "../client.js";
import { toNextRequest } from "../next-compat.js";

/**
 * This contains `param`s, which is a Promise that resolves to an object
 * containing the dynamic route parameters for the current route.
 *
 * See https://nextjs.org/docs/app/api-reference/file-conventions/route#context-optional
 */
export type AppRouteHandlerFnContext = {
  params?: Promise<Record<string, string | string[]>>;
};

/**
 * Handler function for app directory api routes.
 *
 * See: https://nextjs.org/docs/app/api-reference/file-conventions/route
 */
export type AppRouteHandlerFn = (
  req: NextRequest | Request,
  ctx: AppRouteHandlerFnContext
) => Promise<Response> | Response;

/**
 * Wrap an app router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // app/protected-api/route.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default auth0.withApiAuthRequired(function Protected(req) {
 *   const session = auth0.getSession(req);
 *   ...
 * });
 * ```
 *
 * If you visit `/protected-api` without a valid session cookie, you will get a 401 response.
 */
export type WithApiAuthRequiredAppRoute = (
  apiRoute: AppRouteHandlerFn
) => AppRouteHandlerFn;

/**
 * Wrap a page router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // pages/api/protected-route.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default auth0.withApiAuthRequired(function ProtectedRoute(req, res) {
 *   const session = auth0.getSession(req);
 *   ...
 * });
 * ```
 *
 * If you visit `/api/protected-route` without a valid session cookie, you will get a 401 response.
 */
export type WithApiAuthRequiredPageRoute = (
  apiRoute: NextApiHandler
) => NextApiHandler;

/**
 * Protects API routes for Page router pages {@link WithApiAuthRequiredPageRoute} or
 * App router pages {@link WithApiAuthRequiredAppRoute}
 */
export type WithApiAuthRequired = WithApiAuthRequiredAppRoute &
  WithApiAuthRequiredPageRoute;

export const appRouteHandlerFactory =
  (client: Auth0Client): WithApiAuthRequiredAppRoute =>
  (apiRoute) =>
  async (req: NextRequest | Request, params): Promise<NextResponse> => {
    // Normalize plain Request from Next 16 Node runtime
    const nextReq = req instanceof Request ? toNextRequest(req) : req;

    const session = await client.getSession(nextReq);

    if (!session || !session.user) {
      return NextResponse.json(
        {
          error: "not_authenticated",
          description:
            "The user does not have an active session or is not authenticated"
        },
        { status: 401 }
      );
    }

    const apiRes: NextResponse | Response = await apiRoute(nextReq, params);
    const nextApiRes: NextResponse =
      apiRes instanceof NextResponse
        ? apiRes
        : new NextResponse(apiRes.body, apiRes);

    return nextApiRes;
  };

export const pageRouteHandlerFactory =
  (client: Auth0Client): WithApiAuthRequiredPageRoute =>
  (apiRoute) =>
  async (req, res) => {
    const session = await client.getSession(req);

    if (!session || !session.user) {
      res.status(401).json({
        error: "not_authenticated",
        description:
          "The user does not have an active session or is not authenticated"
      });
      return;
    }

    await apiRoute(req, res);
  };
