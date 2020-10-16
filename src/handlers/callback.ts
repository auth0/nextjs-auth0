import { NextApiRequest, NextApiResponse } from 'next';

import IAuth0Settings from '../settings';
// import { ISession } from '../session/session';

import { applyMw, assertReqRes } from './utils';

// export type CallbackOptions = {
//   redirectTo?: string;
//   onUserLoaded?: (
//     req: NextApiRequest,
//     res: NextApiResponse,
//     session: ISession,
//     state: Record<string, any>
//   ) => Promise<ISession>;
// };

export default function callbackHandler(
  settings: IAuth0Settings
) {
  return async (req: NextApiRequest, res: NextApiResponse /*options?: CallbackOptions */): Promise<void> => {
    assertReqRes(req, res);

    const [ , resOidc ] = await applyMw(req, res, settings);

    await (resOidc as any).callback();
  };
}
