import { NextApiResponse, NextApiRequest } from 'next';
import { applyMw, assertReqRes } from './utils';

// import tokenCacheHandler from './token-cache';
// import { ISessionStore } from '../session/store';
// import { IOidcClientFactory } from '../utils/oidc-client';

export type ProfileOptions = {
  refetch?: boolean;
};

export default function profileHandler(config) {
  return async (req: NextApiRequest, res: NextApiResponse/*, options?: ProfileOptions*/): Promise<void> => {
    assertReqRes(req, res);

    const [ reqOidc ] = await applyMw(req, res, config);

    if (!(reqOidc as any).isAuthenticated()) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    // if (options && options.refetch) {
    // }

    res.json((reqOidc as any).user);
  };
}
