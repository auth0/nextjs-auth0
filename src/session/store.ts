import { IncomingMessage, ServerResponse } from 'http';

import { ISession } from './session';

export interface ISessionStore {
  /**
   * Read the session.
   * @param req The HTTP Request.
   */
  read(req: IncomingMessage): Promise<ISession | null | undefined>;

  /**
   * Persist the session.
   * @param req The HTTP request.
   * @param res The HTTP response.
   * @param session The session to persist.
   */
  save(req: IncomingMessage, res: ServerResponse, session: ISession): Promise<ISession | null | undefined>;
}
