import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, logoutHandler } from '../auth0-session';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

/**
 * Custom options to pass to logout.
 *
 * @category Server
 */
export interface LogoutOptions {
  /**
   *  URL to returnTo after logout, overrides the
   *  Default in {@link Config.routes.postLogoutRedirect routes.postLogoutRedirect}
   */
  returnTo?: string;
}

/**
 * The handler for the `api/auth/logout` route.
 *
 * @category Server
 */
export type HandleLogout = (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void>;

/**
 * @ignore
 */
export default function handleLogoutFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache
): HandleLogout {
  const handler = logoutHandler(config, getClient, sessionCache);
  return async (req, res, options): Promise<void> => {
    assertReqRes(req, res);
    return handler(req, res, options);
  };
}
