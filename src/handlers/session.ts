import { IncomingMessage } from 'http';

import { ISession } from '../session/session';
import { ISessionStore } from '../session/store';

export default function sessionHandler(sessionStore: ISessionStore) {
  return (req: IncomingMessage): Promise<ISession | null | undefined> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    return sessionStore.read(req);
  };
}
