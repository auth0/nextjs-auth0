import { NextApiRequest, NextApiResponse } from 'next';
import { Config, CookieStore } from '../auth0-session';
import { ITokenCache } from '../tokens/token-cache';
import SessionTokenCache from '../tokens/session-token-cache';

export default function tokenCacheHandler(config: Config, sessionStore: CookieStore) {
  return (req: NextApiRequest, res: NextApiResponse): ITokenCache => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    return new SessionTokenCache(config, sessionStore, req, res);
  };
}
