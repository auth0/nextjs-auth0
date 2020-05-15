import { NextApiRequest } from 'next';

import { ISession } from '../session/session';
import { ISessionStore } from '../session/store';

export default function sessionHandler(sessionStore: ISessionStore) {
  return (req: NextApiRequest): Promise<ISession | null | undefined> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    return sessionStore.read(req);
  };
}
