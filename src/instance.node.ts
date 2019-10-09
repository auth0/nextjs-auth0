import handlers from './handlers';

import getClient from './utils/oidc-client';
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';

import { ISessionStore } from './session/store';
import CookieSessionStore from './session/cookie-store';
import CookieSessionStoreSettings from './session/cookie-store/settings';

export default function createInstance(settings: IAuth0Settings): ISignInWithAuth0 {
  if (!settings.session) {
    throw new Error('The session configuration is required');
  }

  const clientProvider = getClient(settings);

  const sessionSettings = new CookieSessionStoreSettings(settings.session);
  const store: ISessionStore = new CookieSessionStore(sessionSettings);

  return {
    handleLogin: handlers.LoginHandler(settings, clientProvider),
    handleLogout: handlers.LogoutHandler(settings, sessionSettings),
    handleCallback: handlers.CallbackHandler(settings, clientProvider, store),
    handleProfile: handlers.ProfileHandler(store),
    getSession: handlers.SessionHandler(store),
    requireAuthentication: handlers.RequireAuthentication(store)
  };
}
