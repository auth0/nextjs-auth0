import { NextApiResponse, NextApiRequest } from 'next';
import { SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

export interface ApiRoute {
  (req: NextApiRequest, res: NextApiResponse): Promise<void>;
}

export type WithApiAuthRequired = (apiRoute: ApiRoute) => ApiRoute;

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
