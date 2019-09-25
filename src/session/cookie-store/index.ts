import Iron from '@hapi/iron';
import { IncomingMessage, ServerResponse } from 'http';

import { ISessionStore } from '../store';
import Session, { ISession } from '../session';
import CookieSessionStoreSettings from './settings';
import { setCookie, parseCookies } from '../../utils/cookies';

export default class CookieSessionStore implements ISessionStore {
  private settings: CookieSessionStoreSettings;

  constructor(settings: CookieSessionStoreSettings) {
    this.settings = settings;
  }

  /**
   * Read the session from the cookie.
   * @param req HTTP request
   */
  async read(req: IncomingMessage): Promise<ISession | null> {
    const { cookieSecret, cookieName } = this.settings;

    const cookies = parseCookies(req);
    const cookie = cookies[cookieName];
    if (!cookie || cookie.length === 0) {
      return null;
    }

    const unsealed = await Iron.unseal(cookies[cookieName], cookieSecret, Iron.defaults);
    if (!unsealed) {
      return null;
    }

    return unsealed as ISession;
  }

  /**
   * Write the session to the cookie.
   * @param req HTTP request
   */
  async save(_: IncomingMessage, res: ServerResponse, session: ISession): Promise<void> {
    const { cookieSecret, cookieName, cookiePath, cookieLifetime } = this.settings;

    const { idToken, accessToken, refreshToken, user, createdAt } = session;
    const persistedSession = new Session(user, createdAt);

    if (this.settings.storeIdToken && idToken) {
      persistedSession.idToken = idToken;
    }

    if (this.settings.storeAccessToken && accessToken) {
      persistedSession.accessToken = accessToken;
    }

    if (this.settings.storeRefreshToken && refreshToken) {
      persistedSession.refreshToken = refreshToken;
    }

    const encryptedSession = await Iron.seal(persistedSession, cookieSecret, Iron.defaults);
    setCookie(res, {
      name: cookieName,
      value: encryptedSession,
      path: cookiePath,
      maxAge: cookieLifetime
    });
  }
}
