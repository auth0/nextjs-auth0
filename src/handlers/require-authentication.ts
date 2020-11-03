import { NextApiResponse, NextApiRequest } from 'next';
import SessionCache from '../session/store';

export interface IApiRoute {
  (req: NextApiRequest, res: NextApiResponse): Promise<void>;
}

export default function requireAuthentication(sessionCache: SessionCache, applyCookies: (fn: Function) => any) {
  return (apiRoute: IApiRoute): IApiRoute =>
    applyCookies(
      async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
        if (!req) {
          throw new Error('Request is not available');
        }

        if (!res) {
          throw new Error('Response is not available');
        }

        const session = sessionCache.get(req);
        if (!session || !session.user) {
          res.status(401).json({
            error: 'not_authenticated',
            description: 'The user does not have an active session or is not authenticated'
          });
          return;
        }

        await apiRoute(req, res);
      }
    );
}
