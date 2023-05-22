import { IncomingMessage } from 'http';
import { NextApiResponse, NextApiRequest } from 'next';
import { HandleLogout as BaseHandleLogout } from '../auth0-session';
import { assertReqRes } from '../utils/assert';
import { HandlerErrorCause, LogoutHandlerError } from '../utils/errors';

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
export type LogoutOptionsProvider = (req: NextApiRequest) => LogoutOptions;

/**
 * Use this to customize the default logout handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
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
 * // pages/api/auth/[auth0].js
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
  const logout: LogoutHandler = async (req: NextApiRequest, res: NextApiResponse, options = {}): Promise<void> => {
    try {
      assertReqRes(req, res);
      return await handler(req, res, options);
    } catch (e) {
      throw new LogoutHandlerError(e as HandlerErrorCause);
    }
  };
  return (
    reqOrOptions: NextApiRequest | LogoutOptionsProvider | LogoutOptions,
    res?: NextApiResponse,
    options?: LogoutOptions
  ): any => {
    if (reqOrOptions instanceof IncomingMessage && res) {
      return logout(reqOrOptions, res, options);
    }
    if (typeof reqOrOptions === 'function') {
      return (req: NextApiRequest, res: NextApiResponse) => logout(req, res, reqOrOptions(req));
    }
    return (req: NextApiRequest, res: NextApiResponse) => logout(req, res, reqOrOptions as LogoutOptions);
  };
}
