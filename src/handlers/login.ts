import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, loginHandler, LoginOptions, TransientStore } from '../auth0-session';
import isSafeRedirect from '../utils/url-helpers';
import { assertReqRes } from '../utils/assert';

export type HandleLogin = (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions) => Promise<void>;

export default function handleLoginFactory(
  config: Config,
  getClient: ClientFactory,
  transientHandler: TransientStore
): HandleLogin {
  const handler = loginHandler(config, getClient, transientHandler);
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
