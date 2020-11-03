import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, loginHandler as getLoginHandler, LoginOptions } from '../auth0-session';
import isSafeRedirect from '../utils/url-helpers';
import TransientCookieHandler from '../auth0-session/transient-handler';

export default function loginHandler(
  config: Config,
  getClient: ClientFactory,
  transientHandler: TransientCookieHandler
): (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions) => Promise<void> {
  const handler = getLoginHandler(config, getClient, transientHandler);
  return async (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions): Promise<void> => {
    if (req.query.returnTo) {
      if (typeof req.query.returnTo !== 'string') {
        throw new Error('Invalid value provided for returnTo, must be a string');
      }

      if (!isSafeRedirect(req.query.returnTo)) {
        throw new Error('Invalid value provided for returnTo, must be a relative url');
      }

      options = { ...options, returnTo: req.query.returnTo };
    }

    return handler(req, res, options);
  };
}
