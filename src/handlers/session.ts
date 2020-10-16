import { IncomingMessage } from 'http';

// import { ISession } from '../session/session';
// import { ISessionStore } from '../session/store';
import { applyMw, assertReqRes } from './utils';

export default function sessionHandler(config) {
  return async (req: IncomingMessage, res) => {

    assertReqRes(req, res);

    const [ reqOidc ] = await applyMw(req, res, config);
    return reqOidc;
  };
}
