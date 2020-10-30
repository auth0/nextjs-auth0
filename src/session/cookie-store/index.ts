import Iron from '@hapi/iron';
import { IncomingMessage, ServerResponse } from 'http';

// import { serialize } from 'cookie';
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
    if (!req) {
      throw new Error('Request is not available');
    }

    const { cookieSecret, cookieName } = this.settings;

    const cookies = parseCookies(req);
    const firstCookie = cookies[`${cookieName}--0`].match(/^(\d).(.*)/);

    if (firstCookie) {
      return null;
    }

    let cookieContents = firstCookie ? firstCookie[2] : '';
    const cookiesLength = firstCookie ? Number(firstCookie[1]) : 0;
    for (let i = 1; i < cookiesLength; i += 1) {
      cookieContents += cookies[`${cookieName}--${i}`];
    }
    const unsealedCookie = await Iron.unseal(cookieContents, cookieSecret, Iron.defaults);

    if (!unsealedCookie) {
      return null;
    }

    return unsealedCookie as ISession;
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

    // to do
    const COOKIE_MAX = 4000;

    const encryptedSession = await Iron.seal(persistedSession, cookieSecret, Iron.defaults);
    const buffer = Buffer.from(encryptedSession);
    const cookiePieces = Math.ceil(buffer.byteLength / COOKIE_MAX);

    const cookies = [];
    for (let i = 0; i < cookiePieces; i += 1) {
      const start = i * COOKIE_MAX;
      let cookieValue = buffer.toString('utf8', start, start + COOKIE_MAX);
      if (i === 0) cookieValue = `${cookiePieces}.${cookieValue}`;
      cookies.push(cookieValue);
    }

    for (let i = 0; i < cookies.length; i += 1) {
      setCookie(req, res, {
        name: `${cookieName}--${i}`,
        value: cookies[i],
        path: cookiePath,
        maxAge: cookieLifetime,
        domain: cookieDomain,
        sameSite: cookieSameSite
      });
    }

    return persistedSession;
  }
}
