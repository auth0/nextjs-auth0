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
}

/**
 * The handler for the `/api/auth/logout` API route.
 *
 * @throws {@link HandlerError}
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
      return await handler(req, res, options);
    } catch (e) {
      throw new LogoutHandlerError(e as HandlerErrorCause);
    }
  };
}
