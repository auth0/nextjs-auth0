import { CookieSerializeOptions } from 'cookie';
import createDebug from '../utils/debug';
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
  private store?: SessionStore<Session>;

  private async getStore(): Promise<SessionStore<Session>> {
    if (!this.store) {
      const config = await this.getConfig();
      this.store = config.session.store as SessionStore<Session>;
    }
    return this.store;
  }

  private async getKeys(): Promise<Uint8Array[]> {
    if (!this.keys) {
      const config = await this.getConfig();
      const secret = config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(signing));
    }
    return this.keys;
  }

  async getSession(req: Auth0RequestCookies): Promise<SessionPayload<Session> | undefined | null> {
    const config = await this.getConfig();
    const { name: sessionName } = config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    const sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    if (sessionId) {
      const store = await this.getStore();
      debug('reading session from %s store', sessionId);
      return store.get(sessionId);
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
    const config = await this.getConfig();
    const store = await this.getStore();
    const { name: sessionName, genId } = config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    let sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    // If this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session id to prevent session fixation issue.
    if (sessionId && isNewSession) {
      debug('regenerating session id %o to prevent session fixation', sessionId);
      await store.delete(sessionId);
      sessionId = undefined;
    }

    if (!sessionId) {
      sessionId = await genId!(req, session);
      debug('generated new session id %o', sessionId);
    }
    debug('set session %o', sessionId);
    const cookieValue = await generateCookieValue(sessionName, sessionId, keys[0]);
    res.setCookie(sessionName, cookieValue, cookieOptions);
    await store.set(sessionId, {
      header: { iat, uat, exp },
      data: session
    });
  }

  async deleteSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    cookieOptions: CookieSerializeOptions
  ): Promise<void> {
    const config = await this.getConfig();
    const { name: sessionName } = config.session;
    const cookies = req.getCookies();
    const keys = await this.getKeys();
    const sessionId = await getCookieValue(sessionName, cookies[sessionName], keys);

    if (sessionId) {
      const store = await this.getStore();
      debug('deleting session %o', sessionId);
      res.clearCookie(sessionName, cookieOptions);
      await store.delete(sessionId);
    }
  }
}
