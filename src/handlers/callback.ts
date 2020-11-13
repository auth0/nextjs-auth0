import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, callbackHandler, TransientStore } from '../auth0-session';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

export type HandleCallback = (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

export default function handleLoginFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache,
  transientHandler: TransientStore
): HandleCallback {
  const handler = callbackHandler(config, getClient, sessionCache, transientHandler);
  return async (req, res): Promise<void> => {
    assertReqRes(req, res);
    return handler(req, res);
  };
}
