import { IncomingMessage, ServerResponse } from 'http';

import { ISessionStore } from '../session/store';
import { ITokenCache } from '../tokens/token-cache';
import { IOidcClientFactory } from '../utils/oidc-client';
import SessionTokenCache from '../tokens/session-token-cache';

export default function tokenCacheHandler(clientProvider: IOidcClientFactory, sessionStore: ISessionStore) {
  return (req: IncomingMessage, res: ServerResponse): ITokenCache => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    return new SessionTokenCache(sessionStore, clientProvider, req, res);
  };
}
