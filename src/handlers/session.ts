import { IncomingMessage, ServerResponse } from 'http';
import { Session, CookieStore } from '../auth0-session';

export default function sessionHandler(sessionStore: CookieStore) {
  return (req: IncomingMessage, res: ServerResponse): Session | null | undefined => {
    if (!req) {
      throw new Error('Request is not available');
    }

    return sessionStore.get(req, res);
  };
}
