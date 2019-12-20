import { NextApiResponse, NextApiRequest } from 'next';

import { ISession } from '../session/session';
import { ISessionStore } from '../session/store';

export default function sessionHandler(sessionStore: ISessionStore) {
  return (req: NextApiRequest, res: NextApiResponse): Promise<ISession | null | undefined> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    return sessionStore.read(req, res);
  };
}
