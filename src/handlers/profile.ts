import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory } from '../auth0-session';
import { SessionCache, Session, fromJson, GetAccessToken } from '../session';
import { assertReqRes } from '../utils/assert';

export type ProfileOptions = {
  refetch?: boolean;
};

export type HandleProfile = (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void>;

export default function profileHandler(
  sessionCache: SessionCache,
  getClient: ClientFactory,
  getAccessToken: GetAccessToken
): HandleProfile {
  return async (req, res, options): Promise<void> => {
    assertReqRes(req, res);

    if (!sessionCache.isAuthenticated(req, res)) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    const session = sessionCache.get(req, res) as Session;

    if (options && options.refetch) {
      const { accessToken } = await getAccessToken(req, res);
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
        res,
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
