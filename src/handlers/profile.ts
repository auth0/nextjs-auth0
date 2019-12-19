import { NextApiResponse, NextApiRequest } from 'next';
import { ISessionStore } from '../session/store';
import { IOidcClientFactory } from '../utils/oidc-client';

export type ProfileOptions = {
  refetch?: boolean;
};

export default function profileHandler(clientProvider: IOidcClientFactory, sessionStore: ISessionStore) {
  return async (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    const session = await sessionStore.read(req, res);
    if (!session || !session.user) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    if (options && options.refetch) {
      if (!session.accessToken) {
        throw new Error('The access token needs to be saved in the session for the user to be fetched');
      }

      const client = await clientProvider();
      const userInfo = await client.userinfo(session.accessToken);

      await sessionStore.save(req, res, { ...session, user: userInfo });
      res.json(userInfo);
      return;
    }

    res.json(session.user);
  };
}
