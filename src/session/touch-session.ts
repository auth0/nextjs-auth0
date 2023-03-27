import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

/**
 * Touch the session object. If rolling sessions are enabled and autoSave is disabled, you will need
 * to call this method to update the session expiry.
 *
 * ```js
 * // pages/api/graphql.js
 * import { touchSession } from '@auth0/nextjs-auth0';
 *
 * export default async function graphql(req, res) {
 *   await touchSession(req, res);
 *
 *  // ...
 * };
 * ```
 *
 * @category Server
 */
export type TouchSession = (
  req: IncomingMessage | NextApiRequest,
  res: ServerResponse | NextApiResponse
) => Promise<void>;

/**
 * @ignore
 */
export default function touchSessionFactory(sessionCache: SessionCache): TouchSession {
  return async (req, res) => {
    assertReqRes(req, res);
    const session = await sessionCache.get(req, res);
    if (!session) {
      return;
    }
    await sessionCache.save(req, res);
  };
}
