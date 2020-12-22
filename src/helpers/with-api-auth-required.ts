import { NextApiResponse, NextApiRequest, NextApiHandler } from 'next';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

export type WithApiAuthRequired = (apiRoute: NextApiHandler) => NextApiHandler;

export default function withApiAuthFactory(sessionCache: SessionCache): WithApiAuthRequired {
  return (apiRoute) => async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    assertReqRes(req, res);

    const session = sessionCache.get(req, res);
    if (!session || !session.user) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    await apiRoute(req, res);
  };
}
