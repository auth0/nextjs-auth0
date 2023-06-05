import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { get, set, Session, SessionCache } from '../session';

/**
 * Update the session object. The provided `session` object will replace the existing session.
 *
 * **Note** you can't use this method to login or logout - you should use the login and logout handlers for this.
 * If no session is provided, it doesn't contain a user or the user is not authenticated; this is a no-op.
 *
 * ```js
 * // pages/api/update-user.js
 * import { getSession, updateSession } from '@auth0/nextjs-auth0';
 *
 * export default async function updateSession(req, res) {
 *   if (req.method === 'PUT') {
 *     const session = await getSession(req, res);
 *     updateSession(req, res, { ...session, user: { ...session.user, foo: req.query.foo } });
 *     res.json({ success: true });
 *   }
 * };
 * ```
 *
 * @category Server
 */
export type UpdateSession = (
  req?: IncomingMessage | NextApiRequest | NextRequest | Session,
  res?: ServerResponse | NextApiResponse | NextResponse,
  user?: Session
) => Promise<void>;

/**
 * @ignore
 */
export default function updateSessionFactory(sessionCache: SessionCache): UpdateSession {
  return async (reqOrSession, res, newSession) => {
    const session = (res ? newSession : reqOrSession) as Session | undefined;
    const req = (res ? reqOrSession : undefined) as IncomingMessage | NextApiRequest | NextRequest | undefined;

    const [prevSession, iat] = await get({ sessionCache, req, res });
    if (!prevSession || !session || !session.user) {
      return;
    }
    await set({ req, res, session, sessionCache, iat });
  };
}
