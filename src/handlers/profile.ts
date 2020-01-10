import { NextApiResponse, NextApiRequest } from 'next';

import tokenCacheHandler from './token-cache';
import { ISessionStore } from '../session/store';
import { IOidcClientFactory } from '../utils/oidc-client';

export type ProfileOptions = {
  refetch?: boolean;
};

export default function profileHandler(sessionStore: ISessionStore, clientProvider: IOidcClientFactory) {
  return async (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    const session = await sessionStore.read(req);
    if (!session || !session.user) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    if (options && options.refetch) {
      const tokenCache = tokenCacheHandler(clientProvider, sessionStore)(req, res);
      const { accessToken } = await tokenCache.getAccessToken();
      if (!accessToken) {
        throw new Error('No access token available to refetch the profile');
      }

      const client = await clientProvider();
      const userInfo = await client.userinfo(accessToken);

      const updatedUser = {
        ...session.user,
        ...userInfo
      };

      await sessionStore.save(req, res, {
        ...session,
        user: updatedUser
      });

      res.json(updatedUser);
      return;
    }

    res.json(session.user);
  };
}
