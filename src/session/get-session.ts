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
  req?: IncomingMessage | NextApiRequest | NextRequest,
  res?: ServerResponse | NextApiResponse | NextResponse
) => Promise<Session | null | undefined>;

/**
 * @ignore
 */
export default function sessionFactory(sessionCache: SessionCache) {
  return async (
    req?: IncomingMessage | NextApiRequest | NextRequest,
    res?: ServerResponse | NextApiResponse | NextResponse
  ) => {
    const [session] = await get({ req, res, sessionCache });
    return session;
  };
}
