import { NextApiResponse, NextApiRequest } from 'next';
import { AuthorizationParameters, HandleLogin as BaseHandleLogin } from '../auth0-session';
import isSafeRedirect from '../utils/url-helpers';
import { assertReqRes } from '../utils/assert';

/**
 * Use this to store additional state for the user before they visit the Identity Provider to login.
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * const getLoginState = (req, loginOptions) => {
 *   return { basket_id: getBasketId(req) };
 * };
 *
 * export handleAuth({
 *   async login(req, res) {
 *     try {
 *       await handleLogin(req, res, { getLoginState });
 *     } catch (error) {
 *       res.status(error.status || 500).end(error.message);
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type GetLoginState = (req: NextApiRequest, options: LoginOptions) => { [key: string]: any };

/**
 * Custom options to pass to login.
 *
 * @category Server
 */
export interface LoginOptions {
  /**
   * Override the default {@link BaseConfig.authorizationParams authorizationParams}
   */
  authorizationParams?: Partial<AuthorizationParameters>;

  /**
   *  URL to return to after login, overrides the Default is {@link BaseConfig.baseURL}
   */
  returnTo?: string;

  /**
   *  Generate a unique state value for use during login transactions.
   */
  getLoginState?: GetLoginState;
}

/**
 * The handler for the `api/auth/login` route.
 *
 * @category Server
 */
export type HandleLogin = (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions) => Promise<void>;

/**
 * @ignore
 */
export default function handleLoginFactory(handler: BaseHandleLogin): HandleLogin {
  return async (req, res, options): Promise<void> => {
    assertReqRes(req, res);
    if (req.query.returnTo) {
      const returnTo = Array.isArray(req.query.returnTo) ? req.query.returnTo[0] : req.query.returnTo;

      if (!isSafeRedirect(returnTo)) {
        throw new Error('Invalid value provided for returnTo, must be a relative url');
      }

      options = { ...options, returnTo };
    }

    return handler(req, res, options);
  };
}
