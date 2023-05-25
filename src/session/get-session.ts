import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { SessionCache, Session, get } from '../session';

/**
 * Get the user's session from the request.
 *
 * @category Server
 */
export type GetSession = (
  req?: IncomingMessage | NextApiRequest,
  res?: ServerResponse | NextApiResponse
) => Promise<Session | null | undefined>;

/**
 * @ignore
 */
export default function sessionFactory(sessionCache: SessionCache) {
  return async (req?: IncomingMessage | NextApiRequest, res?: ServerResponse | NextApiResponse) => {
    const [session] = await get({ req, res, sessionCache });
    return session;
  };
}
