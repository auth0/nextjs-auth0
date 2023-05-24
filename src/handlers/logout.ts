import { NextApiResponse, NextApiRequest } from 'next';
import { HandleLogin as BaseHandleLogin, HandleLogout as BaseHandleLogout } from '../auth0-session';
import { assertReqRes } from '../utils/assert';
import { HandlerErrorCause, LogoutHandlerError } from '../utils/errors';
import { Auth0NextApiRequest, Auth0NextApiResponse, Auth0NextRequest, Auth0NextResponse } from '../http';
import { BaseConfig } from '../config';
import { NextRequest, NextResponse } from 'next/server';

/**
 * Options to customize the logout handler.
 *
 * @see {@link HandleLogout}
 *
 * @category Server
 */
export interface LogoutOptions {
  /**
   * URL to return to after logout. Overrides the default
   * in {@link BaseConfig.routes.postLogoutRedirect routes.postLogoutRedirect}.
   */
  returnTo?: string;

  /**
   * Additional custom parameters to pass to the logout endpoint.
   */
  logoutParams?: { [key: string]: any };
}

/**
 * Options provider for the default logout handler.
 * Use this to generate options that depend on values from the request.
 *
 * @category Server
 */
export type LogoutOptionsProvider = (req: NextApiRequest | NextRequest) => LogoutOptions;

/**
 * Use this to customize the default logout handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogout } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   logout: handleLogout({ returnTo: 'https://example.com' })
 * });
 * ```
 *
 * @example Pass a function that receives the request and returns an options object
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogout } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   logout: handleLogout((req) => {
 *     return { returnTo: 'https://example.com' };
 *   })
 * });
 * ```
 *
 * This is useful for generating options that depend on values from the request.
 *
 * @example Override the logout handler
 *
 * ```js
 * import { handleAuth, handleLogout } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   logout: async (req, res) => {
 *     try {
 *       await handleLogout(req, res, {
 *         returnTo: 'https://example.com'
 *       });
 *     } catch (error) {
 *       console.error(error);
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type HandleLogout = {
  (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions): Promise<void>;
  (provider: LogoutOptionsProvider): LogoutHandler;
  (options: LogoutOptions): LogoutHandler;
};

/**
 * The handler for the `/api/auth/logout` API route.
 *
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type LogoutHandler = (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void>;

/**
 * @ignore
 */
export default function handleLogoutFactory(handler: BaseHandleLogout): HandleLogout {
  const appRouteHandler = appRouteHandlerFactory(handler);
  const pageRouteHandler = pageRouteHandlerFactory(handler);

  return (
    reqOrOptions: NextApiRequest | LogoutOptionsProvider | LogoutOptions,
    res?: NextApiResponse,
    options?: LogoutOptions
  ): any => {
    if (typeof Request !== undefined && reqOrOptions instanceof Request) {
      return appRouteHandler(reqOrOptions as NextRequest, options);
    }
    if ('socket' in reqOrOptions && res) {
      return pageRouteHandler(reqOrOptions as NextApiRequest, res as NextApiResponse, options);
    }
    return (req: NextApiRequest | NextRequest, res: NextApiResponse) => {
      const opts = (typeof reqOrOptions === 'function' ? reqOrOptions(req) : reqOrOptions) as LogoutOptions;

      if (typeof Request !== undefined && reqOrOptions instanceof Request) {
        return appRouteHandler(req as NextRequest, opts);
      }
      return pageRouteHandler(req as NextApiRequest, res as NextApiResponse, opts);
    };
  };
}

const appRouteHandlerFactory: (
  handler: BaseHandleLogin
) => (req: NextRequest, options?: LogoutOptions) => Promise<Response> | Response =
  (handler) =>
  async (req, options = {}) => {
    try {
      const auth0Res = new Auth0NextResponse(new NextResponse());
      await handler(new Auth0NextRequest(req), auth0Res, options);
      return auth0Res.res;
    } catch (e) {
      throw new LogoutHandlerError(e as HandlerErrorCause);
    }
  };

const pageRouteHandlerFactory: (
  handler: BaseHandleLogin
) => (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void> =
  (handler) =>
  async (req, res, options = {}) => {
    try {
      assertReqRes(req, res);
      return await handler(new Auth0NextApiRequest(req), new Auth0NextApiResponse(res), options);
    } catch (e) {
      throw new LogoutHandlerError(e as HandlerErrorCause);
    }
  };
