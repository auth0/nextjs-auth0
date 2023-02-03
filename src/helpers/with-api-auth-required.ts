import { NextApiResponse, NextApiRequest, NextApiHandler } from 'next';
import jwt from 'jsonwebtoken';
import jwkToBuffer from 'jwk-to-pem';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

const extractToken = (req: NextApiRequest) => {
  if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

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
        const jwks: { keys: jwkToBuffer.JWK[] } = await (
          await fetch(`${process.env.AUTH0_ISSUER_BASE_URL}/.well-known/jwks.json`)
        ).json();

        if (jwks && jwks.keys?.[0] == undefined) {
          res.status(401).json({
            error: 'not_authenticated',
            description: 'Invalid JWK Keys'
          });
          return;
        }

        const pem = jwkToBuffer(jwks.keys[0]);

        const token = extractToken(req);
        if (!token) {
          res.status(401).json({
            error: 'not_authenticated',
            description: 'The user does not have an active session or is not authenticated'
          });
          return;
        }

        try {
          jwt.verify(token, pem, {
            algorithms: ['RS256']
          });
        } catch (err) {
          res.status(401).json(err);
          return;
        }
      }

      await apiRoute(req, res);
    };
}
