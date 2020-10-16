import { NextApiRequest, NextApiResponse } from 'next';

// import IAuth0Settings from '../settings';
import { applyMw, assertReqRes } from './utils';

export interface LogoutOptions {
  returnTo?: string;
}

export default function logoutHandler(config) {
  return async (req: NextApiRequest, res: NextApiResponse/*, options?: LogoutOptions*/): Promise<void> => {
    assertReqRes(req, res);
    const [ reqOidc, resOidc ] = await applyMw(req, res, config);
    (req as any).oidc = reqOidc;
    await (resOidc as any).logout(/* options */);
  };
}
