import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionCache, Session, get } from '../session';

/**
 * Get the user's session from the request.
 *
 * @category Server
 */
export type GetSession = (
  ...args: [IncomingMessage, ServerResponse] | [NextApiRequest, NextApiResponse] | [NextRequest, NextResponse] | []
) => Promise<Session | null | undefined>;

/**
 * @ignore
 */
export default function sessionFactory(sessionCache: SessionCache): GetSession {
  return async (req?, res?) => {
    const [session] = await get({ req, res, sessionCache });
    return session;
  };
}
