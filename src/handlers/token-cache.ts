import { NextApiRequest, NextApiResponse } from 'next';

import { ISessionStore } from '../session/store';
import { ITokenCache } from '../tokens/token-cache';
import { IOidcClientFactory } from '../utils/oidc-client';
import SessionTokenCache from '../tokens/session-token-cache';

export default function tokenCacheHandler(clientProvider: IOidcClientFactory, sessionStore: ISessionStore) {
  return (req: NextApiRequest, res: NextApiResponse): ITokenCache => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    return new SessionTokenCache(sessionStore, clientProvider, req, res);
  };
}
