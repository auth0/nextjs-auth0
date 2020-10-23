import {
  ConfigParameters,
  getConfig,
  CookieStore,
  TransientCookieHandler,
  loginHandler,
  logoutHandler,
  callbackHandler,
  clientFactory
} from './auth0-session';
import { profileHandler, sessionHandler, requireAuthentication, tokenCache } from './handlers';

export default function createInstance(params: ConfigParameters) {
  const config = getConfig(params);
  const getClient = clientFactory(config);
  const transientHandler = new TransientCookieHandler(config);
  const sessionStore = new CookieStore(config, getClient);

  return {
    handleLogin: loginHandler(config, getClient, transientHandler),
    handleLogout: logoutHandler(config, getClient, sessionStore),
    handleCallback: callbackHandler(config, getClient, sessionStore, transientHandler),
    handleProfile: profileHandler(sessionStore, getClient),
    getSession: sessionHandler(sessionStore),
    requireAuthentication: requireAuthentication(sessionStore),
    tokenCache: tokenCache(config, sessionStore)
  };
}
