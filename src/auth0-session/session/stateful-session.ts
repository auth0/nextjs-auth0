import { CookieSerializeOptions } from 'cookie';
import createDebug from '../utils/debug';
import { Config } from '../config';
import { AbstractSession, SessionPayload } from './abstract-session';
import { generateCookieValue, getCookieValue } from '../utils/signed-cookies';
import { signing } from '../utils/hkdf';
import { Auth0RequestCookies, Auth0ResponseCookies } from '../http';

const debug = createDebug('stateful-session');

export interface SessionStore<Session> {
  /**
   * Gets the session from the store given a session ID.
   */
  get(sid: string): Promise<SessionPayload<Session> | null | undefined>;

  /**
   * Upsert a session in the store given a session ID and `SessionData`.
   */
  set(sid: string, session: SessionPayload<Session>): Promise<void>;

  /**
   * Destroys the session with the given session ID.
   */
  delete(sid: string): Promise<void>;
}

export class StatefulSession<
  Session extends { [key: string]: any } = { [key: string]: any }
> extends AbstractSession<Session> {
  private keys?: Uint8Array[];
  private store: SessionStore<Session>;

  constructor(protected config: Config) {
    super(config);
    this.store = config.session.store as SessionStore<Session>;
  }

  private async getKeys(): Promise<Uint8Array[]> {
    if (!this.keys) {
      const secret = this.config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(signing));
    }
    return this.keys;
  }

  async getSession(req: Auth0RequestCookies): Promise<SessionPayload<Session> | undefined | null> {
    const { name: sessionName } = this.config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    const sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    if (sessionId) {
      debug('reading session from %s store', sessionId);
      return this.store.get(sessionId);
    }
    return;
  }

  async setSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    session: Session,
    uat: number,
    iat: number,
    exp: number,
    cookieOptions: CookieSerializeOptions,
    isNewSession: boolean
  ): Promise<void> {
    const { name: sessionName, genId } = this.config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    let sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    // If this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session id to prevent session fixation issue.
    if (sessionId && isNewSession) {
      debug('regenerating session id %o to prevent session fixation', sessionId);
      await this.store.delete(sessionId);
      sessionId = undefined;
    }

    if (!sessionId) {
      sessionId = await genId!(req, session);
      debug('generated new session id %o', sessionId);
    }
    debug('set session %o', sessionId);
    const cookieValue = await generateCookieValue(sessionName, sessionId, keys[0]);
    res.setCookie(sessionName, cookieValue, cookieOptions);
    await this.store.set(sessionId, {
      header: { iat, uat, exp },
      data: session
    });
  }

  async deleteSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    cookieOptions: CookieSerializeOptions
  ): Promise<void> {
    const { name: sessionName } = this.config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    const sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    if (sessionId) {
      debug('deleting session %o', sessionId);
      res.clearCookie(sessionName, cookieOptions);
      await this.store.delete(sessionId);
    }
  }
}
