import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { Claims, SessionCache } from '../session';

/**
 * Update the session's user object. The provided user object will replace `session.user`.
 *
 * If no user is provided, or the user is not authenticated, this is a no-op.
 *
 * ```js
 * // pages/api/update-user.js
 * import { getSession, updateUser } from '@auth0/nextjs-auth0';
 *
 * export default async function UpdateUser(req, res) {
 *   if (req.method === 'PUT') {
 *     const { user } = getSession(req, res);
 *     updateUser(req, res, { ...user, foo: req.query.foo });
 *     res.json({ success: true });
 *   }
 * };
 * ```
 *
 * @category Server
 */
export type UpdateUser = (
  req: IncomingMessage | NextApiRequest,
  res: ServerResponse | NextApiResponse,
  user: Claims
) => Promise<void>;

/**
 * @ignore
 */
export default function updateUserFactory(sessionCache: SessionCache): UpdateUser {
  return async (req, res, user) => {
    await sessionCache.init(req, res, false);
    const session = await sessionCache.get(req, res);
    if (!session || !user) {
      return;
    }
    await sessionCache.set(req, res, { ...session, user });
  };
}
