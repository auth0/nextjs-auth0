import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config } from '../auth0-session';
import SessionCache from '../session/store';
import SessionTokenCache from '../tokens/session-token-cache';
import Session, { fromJson } from '../session/session';

export type ProfileOptions = {
  refetch?: boolean;
};

export default function profileHandler(config: Config, sessionCache: SessionCache, getClient: ClientFactory) {
  return async (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    if (!sessionCache.isAuthenticated(req)) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    const session = sessionCache.get(req) as Session;

    if (options && options.refetch) {
      const tokenCache = new SessionTokenCache(getClient, config, sessionCache, req);
      const { accessToken } = await tokenCache.getAccessToken();
      if (!accessToken) {
        throw new Error('No access token available to refetch the profile');
      }

      const client = await getClient();
      const userInfo = await client.userinfo(accessToken);

      const updatedUser = {
        ...session.user,
        ...userInfo
      };

      sessionCache.set(
        req,
        fromJson({
          ...session,
          user: updatedUser
        })
      );

      res.json(updatedUser);
      return;
    }

    res.json(session.user);
  };
}
