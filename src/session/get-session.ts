import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { SessionCache, Session } from '../session';

export type GetSession = (
  req: IncomingMessage | NextApiRequest,
  res: ServerResponse | NextApiResponse
) => Session | null | undefined;

export default function sessionFactory(sessionCache: SessionCache): GetSession {
  return (req, res): Session | null | undefined => {
    return sessionCache.get(req, res);
  };
}
