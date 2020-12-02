import { ConfigParameters, getConfig, CookieStore, TransientStore, clientFactory } from './auth0-session';
import { handlerFactory, callbackHandler, loginHandler, logoutHandler, profileHandler } from './handlers';
import { sessionFactory, accessTokenFactory, SessionCache } from './session/';
import { withPageAuthRequiredFactory, withApiAuthRequiredFactory } from './helpers';
import { SignInWithAuth0 } from './instance';
import version from './version';

export default function createInstance(params: ConfigParameters): SignInWithAuth0 {
  const config = getConfig(params);
  const getClient = clientFactory(config, { name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(config);
  const cookieStore = new CookieStore(config);
  const sessionCache = new SessionCache(config, cookieStore);
  const getSession = sessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(getClient, config, sessionCache);
  const withApiAuthRequired = withApiAuthRequiredFactory(sessionCache);
  const withPageAuthRequired = withPageAuthRequiredFactory(sessionCache);
  const handleLogin = loginHandler(config, getClient, transientStore);
  const handleLogout = logoutHandler(config, getClient, sessionCache);
  const handleCallback = callbackHandler(config, getClient, sessionCache, transientStore);
  const handleProfile = profileHandler(sessionCache, getClient, getAccessToken);
  const handleAuth = handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile });

  return {
    getSession,
    getAccessToken,
    withApiAuthRequired,
    withPageAuthRequired,
    handleLogin,
    handleLogout,
    handleCallback,
    handleProfile,
    handleAuth
  };
}
