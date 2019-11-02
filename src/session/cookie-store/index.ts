import Iron from '@hapi/iron';
import { IncomingMessage, ServerResponse } from 'http';

import { ISessionStore } from '../store';
import Session, { ISession } from '../session';
import CookieSessionStoreSettings from './settings';
import { setCookie, parseCookies } from '../../utils/cookies';
import { IOidcClientFactory } from '../../utils/oidc-client';
import getSessionFromTokenSet from '../../utils/session';

export default class CookieSessionStore implements ISessionStore {
  private settings: CookieSessionStoreSettings;

  private clientProvider: IOidcClientFactory;

  constructor(settings: CookieSessionStoreSettings, clientProvider: IOidcClientFactory) {
    this.settings = settings;
    this.clientProvider = clientProvider;
  }

  /**
   * Read the session from the cookie.
   * @param req HTTP request
   */
  async read(req: IncomingMessage, res: ServerResponse): Promise<ISession | null> {
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

    const { expiresAt, refreshToken } = unsealed as ISession;

    // Check if the token has expired
    if (refreshToken && expiresAt && expiresAt * 1000 < Date.now()) {
      const client = await this.clientProvider();

      // Refresh the token
      const tokenSet = await client.refresh(refreshToken);

      // It doesn't return a new refresh token, so we have to keep the old one
      const session = {
        ...getSessionFromTokenSet(tokenSet),
        refreshToken
      };

      // Save the new session
      return this.save(req, res, session);
    }

    return unsealed as ISession;
  }

  /**
   * Write the session to the cookie.
   * @param req HTTP request
   */
  async save(req: IncomingMessage, res: ServerResponse, session: ISession): Promise<ISession> {
    const { cookieSecret, cookieName, cookiePath, cookieLifetime } = this.settings;

    const { idToken, accessToken, refreshToken, user, createdAt, expiresAt } = session;
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

    if (this.settings.storeRefreshToken && refreshToken && expiresAt) {
      persistedSession.expiresAt = expiresAt;
    }

    const encryptedSession = await Iron.seal(persistedSession, cookieSecret, Iron.defaults);
    setCookie(req, res, {
      name: cookieName,
      value: encryptedSession,
      path: cookiePath,
      maxAge: cookieLifetime
    });
    return persistedSession;
  }
}
