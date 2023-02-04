import { NextApiResponse, NextApiRequest, NextApiHandler } from 'next';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';
import validateJWT from './validateJWT';

/**
 * Wrap an API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // pages/api/protected-route.js
 * import { withApiAuthRequired, getSession } from '@auth0/nextjs-auth0';
 *
 * export default withApiAuthRequired(function ProtectedRoute(req, res) {
 *   const session = getSession(req, res);
 *   ...
 * });
 * ```
 *
 * If you visit `/api/protected-route` without a valid session cookie, you will get a 401 response.
 *
 * @category Server
 */
export type WithApiAuthRequired = (apiRoute: NextApiHandler) => NextApiHandler;

/**
 * @ignore
 */
export default function withApiAuthFactory(sessionCache: SessionCache): WithApiAuthRequired {
  return (apiRoute) =>
    async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
      assertReqRes(req, res);
      const session = await sessionCache.get(req, res);
      if (!session || !session.user) {
        const jwt = validateJWT(req);
        if (!jwt) {
          res.status(401).json({
            error: 'not_authenticated',
            description: 'The user does not have a valid token'
          });
          return;
        }
      }

      await apiRoute(req, res);
    };
}
