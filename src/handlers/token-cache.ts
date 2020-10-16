import { NextApiRequest } from 'next';
import { ClientFactory, Config } from '../auth0-session';
import { ITokenCache } from '../tokens/token-cache';
import SessionTokenCache from '../tokens/session-token-cache';
import SessionCache from '../session/store';

export default function tokenCacheHandler(getClient: ClientFactory, config: Config, sessionCache: SessionCache) {
  return (req: NextApiRequest): ITokenCache => {
    if (!req) {
      throw new Error('Request is not available');
    }

    return new SessionTokenCache(getClient, config, sessionCache, req);
  };
}
