import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, logoutHandler, LogoutOptions } from '../auth0-session';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

export type HandleLogout = (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void>;

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
