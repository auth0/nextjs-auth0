import { ITokenCache } from './tokens/token-cache';
import handlers from './handlers';
import getClient from './utils/oidc-client';
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';
import { ISessionStore } from './session/store';
import CookieSessionStore from './session/cookie-store';
import CookieSessionStoreSettings from './session/cookie-store/settings';

export default function createInstance(settings: IAuth0Settings): ISignInWithAuth0 {
  if (!settings.domain) {
    throw new Error('A valid Auth0 Domain must be provided');
  }

  if (!settings.clientId) {
    throw new Error('A valid Auth0 Client ID must be provided');
  }

  if (!settings.clientSecret) {
    throw new Error('A valid Auth0 Client Secret must be provided');
  }

  if (!settings.session) {
    throw new Error('The session configuration is required');
  }

  if (!settings.session.cookieSecret) {
    throw new Error('A valid session cookie secret is required');
  }

  const clientProvider = getClient(settings);

  const sessionSettings = new CookieSessionStoreSettings(settings.session);
  const store: ISessionStore = new CookieSessionStore(sessionSettings);

  return {
    handleLogin: handlers.LoginHandler(settings, clientProvider),
    handleLogout: handlers.LogoutHandler(settings, sessionSettings),
    handleCallback: handlers.CallbackHandler(settings, clientProvider, store),
    handleProfile: handlers.ProfileHandler(store, clientProvider),
    getSession: handlers.SessionHandler(store),
    requireAuthentication: handlers.RequireAuthentication(store),
    tokenCache: handlers.TokenCache(clientProvider, store)
  };
}
