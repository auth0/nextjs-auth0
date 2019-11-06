import { NextApiResponse, NextApiRequest } from 'next';
import request from 'request';
import { promisify } from 'util';

import IAuth0Settings from '../settings';
import { ISessionStore } from '../session/store';

const [getAsync] = [request.get].map(promisify);

export default function profileHandler(settings: IAuth0Settings, sessionStore: ISessionStore) {
  return async (req: NextApiRequest, res: NextApiResponse, { refetch } = { refetch: false }): Promise<void> => {
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

    if (refetch) {
      if (!session.accessToken) {
        throw new Error('The access token needs to be saved in the session for the user to be fetched');
      }

      const { body: user } = await getAsync({
        baseUrl: `https://${settings.domain}`,
        url: 'userinfo',
        json: true,
        headers: {
          Authorization: `Bearer ${session.accessToken}`
        }
      });

      await sessionStore.save(req, res, { ...session, user });
      res.json(user);
      return;
    }

    res.json(session.user);
  };
}
