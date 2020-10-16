import handlers from './handlers';
import { getConfig, TransientCookieHandler } from './auth0-session';
import { ConfigParameters } from 'auth0-session/config';
import CookieStore from 'auth0-session/cookie-store';

export default function createInstance(params: ConfigParameters) {
  const config = getConfig(params);

  const sessionStore = new CookieStore(config);
  const transient = new TransientCookieHandler(config);

  return {
    handleLogin: handlers.LoginHandler(config),
    handleLogout: handlers.LogoutHandler(config),
    handleCallback: handlers.CallbackHandler(config),
    handleProfile: handlers.ProfileHandler(config),
    getSession: handlers.SessionHandler(config)
    // requireAuthentication: handlers.RequireAuthentication(store),
    // tokenCache: handlers.TokenCache(clientProvider, store)
  };
}
