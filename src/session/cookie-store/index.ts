import Iron from '@hapi/iron';
import { IncomingMessage, ServerResponse } from 'http';

import { ISessionStore } from '../store';
import Session, { ISession } from '../session';
import CookieSessionStoreSettings from './settings';
import { setCookies, parseCookies } from '../../utils/cookies';

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
    if (!req) {
      throw new Error('Request is not available');
    }

    const { cookieSecret, cookieName } = this.settings;

    const cookies = parseCookies(req);
    const cookieCount = cookies[`${cookieName}.c`] || 1;
    let cookie = '';
    for (let i = 0; i < cookieCount; i += 1) {
      const cookiePart = cookies[`${cookieName}.${i}`];
      if (!cookiePart || cookiePart.length === 0) {
        return null; // missing or broken cookie part
      }
      cookie += cookiePart;
    }

    const unsealed = await Iron.unseal(cookie, cookieSecret, Iron.defaults);
    if (!unsealed) {
      return null;
    }

    return unsealed as ISession;
  }

  /**
   * Write the session to the cookie.
   * @param req HTTP request
   */
  async save(req: IncomingMessage, res: ServerResponse, session: ISession): Promise<ISession | null> {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    const { cookieSecret, cookieName, cookiePath, cookieLifetime, cookieDomain, cookieSameSite } = this.settings;

    const { idToken, accessToken, accessTokenExpiresAt, accessTokenScope, refreshToken, user, createdAt } = session;
    const persistedSession = new Session(user, createdAt);

    if (this.settings.storeIdToken && idToken) {
      persistedSession.idToken = idToken;
    }

    if (this.settings.storeAccessToken && accessToken) {
      persistedSession.accessToken = accessToken;
      persistedSession.accessTokenScope = accessTokenScope;
      persistedSession.accessTokenExpiresAt = accessTokenExpiresAt;
    }

    if (this.settings.storeRefreshToken && refreshToken) {
      persistedSession.refreshToken = refreshToken;
    }

    const encryptedSession = await Iron.seal(persistedSession, cookieSecret, Iron.defaults);

    const cookies = [];
    let start = 0;
    do {
      cookies.push({
        name: `${cookieName}.${cookies.length}`,
        value: encryptedSession.slice(start, start + 4000),
        path: cookiePath,
        maxAge: cookieLifetime,
        domain: cookieDomain,
        sameSite: cookieSameSite
      });
      start += 4000;
    } while (encryptedSession.length > start);

    cookies.push({
      name: `${cookieName}.c`,
      value: cookies.length.toString(),
      path: cookiePath,
      maxAge: cookieLifetime,
      domain: cookieDomain,
      sameSite: cookieSameSite
    });

    setCookies(req, res, cookies);

    return persistedSession;
  }
}
