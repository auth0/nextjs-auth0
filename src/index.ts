import { getConfig, CookieStore, TransientStore, clientFactory } from './auth0-session';
import {
  handlerFactory,
  callbackHandler,
  loginHandler,
  logoutHandler,
  profileHandler,
  HandleAuth,
  HandleLogin,
  HandleProfile,
  HandleLogout,
  HandleCallback
} from './handlers';
import { sessionFactory, accessTokenFactory, SessionCache, GetSession, GetAccessToken } from './session/';
import {
  withPageAuthRequiredFactory,
  withApiAuthRequiredFactory,
  WithPageAuthRequired,
  WithApiAuthRequired
} from './helpers';
import { InitAuth0, SignInWithAuth0 } from './instance';
import version from './version';
import { getParams } from './config';

let instance: SignInWithAuth0;

function getInstance(): SignInWithAuth0 {
  if (instance) {
    return instance;
  }
  instance = initAuth0();
  return instance;
}

export const initAuth0: InitAuth0 = (params) => {
  const config = getConfig(getParams(params));
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
};

export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => getInstance().withApiAuthRequired(...args);
export const withPageAuthRequired: WithPageAuthRequired = (...args) => getInstance().withPageAuthRequired(...args);
export const handleLogin: HandleLogin = (...args) => getInstance().handleLogin(...args);
export const handleLogout: HandleLogout = (...args) => getInstance().handleLogout(...args);
export const handleCallback: HandleCallback = (...args) => getInstance().handleCallback(...args);
export const handleProfile: HandleProfile = (...args) => getInstance().handleProfile(...args);
export const handleAuth: HandleAuth = (...args) => getInstance().handleAuth(...args);

export { UserProvider, UserProfile, UserContext, useUser, withPageAuthenticationRequired } from './frontend';
