import { IncomingMessage, ServerResponse } from 'http';

import { ISession } from '../session';
import { ISessionStore } from '../store';

export default class MemoryStore implements ISessionStore {
  private session: ISession | null;

  constructor(session?: ISession) {
    if (session === undefined) {
      this.session = null;
    } else {
      this.session = session;
    }
  }

  /**
   * Read the session from the cookie.
   * @param req HTTP request
   * @param res HTTP response
   */
  async read(): Promise<ISession | null> {
    return this.session;
  }

  /**
   * Write the session to the cookie.
   * @param req HTTP request
   */
  async save(_req: IncomingMessage, _res: ServerResponse, session: ISession): Promise<ISession> {
    this.session = session;
    return session;
  }
}
