import { ConfigParameters, getConfig, CookieStore, TransientStore, clientFactory } from './auth0-session';
import { profileHandler, loginHandler, logoutHandler, callbackHandler } from './handlers';
import { sessionFactory, accessTokenFactory, SessionCache } from './session/';
import { withPageAuthFactory, withApiAuthFactory } from './helpers';
import { SignInWithAuth0 } from './instance';
import version from './version';

export default function createInstance(params: ConfigParameters): SignInWithAuth0 {
  const config = getConfig(params);
  const getClient = clientFactory(config, { name: 'nextjs-auth0', version });
  const transientHandler = new TransientStore(config);
  const cookieStore = new CookieStore(config);
  const sessionCache = new SessionCache(config, cookieStore);
  const getSession = sessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(getClient, config, sessionCache);

  return {
    handleLogin: loginHandler(config, getClient, transientHandler),
    handleLogout: logoutHandler(config, getClient, sessionCache),
    handleCallback: callbackHandler(config, getClient, sessionCache, transientHandler),
    handleProfile: profileHandler(sessionCache, getClient, getAccessToken),
    withApiAuth: withApiAuthFactory(sessionCache),
    withPageAuth: withPageAuthFactory(sessionCache),
    getSession,
    getAccessToken
  };
}
