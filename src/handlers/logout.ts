import { NextApiResponse, NextApiRequest } from 'next';
import { HandleLogout as BaseHandleLogout } from '../auth0-session';
import { assertReqRes } from '../utils/assert';
import { HandlerError } from '../utils/errors';
import isSafeRedirect from '../utils/url-helpers';

/**
 * Custom options to pass to logout.
 *
 * @category Server
 */
export interface LogoutOptions {
  /**
   *  URL to returnTo after logout, overrides the
   *  Default in {@link BaseConfig.routes.postLogoutRedirect routes.postLogoutRedirect}
   */
  returnTo?: string;
}

/**
 * The handler for the `api/auth/logout` route.
 *
 * @throws {@Link HandlerError}
 *
 * @category Server
 */
export type HandleLogout = (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void>;

/**
 * @ignore
 */
export default function handleLogoutFactory(handler: BaseHandleLogout): HandleLogout {
  return async (req, res, options): Promise<void> => {
    try {
      assertReqRes(req, res);
      if (req.query.returnTo) {
        const returnTo = Array.isArray(req.query.returnTo) ? req.query.returnTo[0] : req.query.returnTo;

        if (!isSafeRedirect(returnTo)) {
          throw new Error('Invalid value provided for returnTo, must be a relative url');
        }

        options = { ...options, returnTo };
      }

      return await handler(req, res, options);
    } catch (e) {
      throw new HandlerError(e);
    }
  };
}
