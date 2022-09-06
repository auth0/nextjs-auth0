import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { SessionCache, Session } from '../session';
import { assertReqRes } from '../utils/assert';

/**
 * Get the user's session from the request.
 *
 * @category Server
 */
export type GetSession = (
  req: IncomingMessage | NextApiRequest,
  res: ServerResponse | NextApiResponse
) => Promise<Session | null | undefined>;

/**
 * @ignore
 */
export default function sessionFactory(sessionCache: SessionCache): GetSession {
  return (req, res) => {
    assertReqRes(req, res);
    return sessionCache.get(req, res);
  };
}
