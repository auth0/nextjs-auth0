import { NextApiRequest } from 'next';
import SessionCache from '../session/store';
import Session from '../session/session';

export default function sessionHandler(sessionCache: SessionCache) {
  return (req: NextApiRequest): Session | null | undefined => {
    if (!req) {
      throw new Error('Request is not available');
    }

    return sessionCache.get(req);
  };
}
