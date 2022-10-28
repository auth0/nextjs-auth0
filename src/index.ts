import crypto from 'crypto';
import {
  NodeCookies as Cookies,
  StatelessSession,
  StatefulSession,
  SessionStore as GenericSessionStore,
  TransientStore,
  clientFactory,
  loginHandler as baseLoginHandler,
  logoutHandler as baseLogoutHandler,
  callbackHandler as baseCallbackHandler
} from './auth0-session';
import {
  handlerFactory,
  callbackHandler,
  loginHandler,
  logoutHandler,
  profileHandler,
  Handlers,
  HandleAuth,
  HandleLogin,
  HandleProfile,
  HandleLogout,
  HandleCallback,
  LoginOptions,
  LogoutOptions,
  GetLoginState,
  ProfileOptions,
  CallbackOptions,
  AfterCallback,
  AfterRefetch,
  OnError
} from './handlers';
import {
  sessionFactory,
  accessTokenFactory,
  SessionCache,
  GetSession,
  GetAccessToken,
  Session,
  AccessTokenRequest,
  GetAccessTokenResult,
  Claims,
  updateSessionFactory,
  UpdateSession
} from './session/';
import {
  withPageAuthRequiredFactory,
  withApiAuthRequiredFactory,
  WithApiAuthRequired,
  WithPageAuthRequired,
  GetServerSidePropsResultWithSession,
  WithPageAuthRequiredOptions,
  PageRoute
} from './helpers';
import { InitAuth0, SignInWithAuth0 } from './instance';
import version from './version';
import { getConfig, getLoginUrl, ConfigParameters } from './config';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';
import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';

let instance: SignInWithAuth0 & { sessionCache: SessionCache };

const genid = () => crypto.randomBytes(16).toString('hex');

// For using managed instance with named exports.
function getInstance(): SignInWithAuth0 & { sessionCache: SessionCache } {
  setIsUsingNamedExports();
  if (instance) {
    return instance;
  }
  instance = _initAuth();
  return instance;
}

// For creating own instance.
export const initAuth0: InitAuth0 = (params) => {
  setIsUsingOwnInstance();
  const { sessionCache, ...publicApi } = _initAuth(params); // eslint-disable-line @typescript-eslint/no-unused-vars
  return publicApi;
};

export const _initAuth = (params?: ConfigParameters): SignInWithAuth0 & { sessionCache: SessionCache } => {
  const { baseConfig, nextConfig } = getConfig({ ...params, session: { genid, ...params?.session } });

  // Init base layer (with base config)
  const getClient = clientFactory(baseConfig, { name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(baseConfig);

  const sessionStore = baseConfig.session.store
    ? new StatefulSession<IncomingMessage | NextApiRequest, ServerResponse | NextApiResponse, Session>(
        baseConfig,
        Cookies
      )
    : new StatelessSession<IncomingMessage | NextApiRequest, ServerResponse | NextApiResponse, Session>(
        baseConfig,
        Cookies
      );
  const sessionCache = new SessionCache(baseConfig, sessionStore);
  const baseHandleLogin = baseLoginHandler(baseConfig, getClient, transientStore);
  const baseHandleLogout = baseLogoutHandler(baseConfig, getClient, sessionCache);
  const baseHandleCallback = baseCallbackHandler(baseConfig, getClient, sessionCache, transientStore);

  // Init Next layer (with next config)
  const getSession = sessionFactory(sessionCache);
  const updateSession = updateSessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(nextConfig, getClient, sessionCache);
  const withApiAuthRequired = withApiAuthRequiredFactory(sessionCache);
  const withPageAuthRequired = withPageAuthRequiredFactory(nextConfig.routes.login, () => sessionCache);
  const handleLogin = loginHandler(baseHandleLogin, nextConfig, baseConfig);
  const handleLogout = logoutHandler(baseHandleLogout);
  const handleCallback = callbackHandler(baseHandleCallback, nextConfig);
  const handleProfile = profileHandler(getClient, getAccessToken, sessionCache);
  const handleAuth = handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile });

  return {
    sessionCache,
    getSession,
    updateSession,
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

/* c8 ignore start */
const getSessionCache = () => getInstance().sessionCache;
export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const updateSession: UpdateSession = (...args) => getInstance().updateSession(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => getInstance().withApiAuthRequired(...args);
export const withPageAuthRequired: WithPageAuthRequired = withPageAuthRequiredFactory(getLoginUrl(), getSessionCache);
export const handleLogin: HandleLogin = ((...args: Parameters<HandleLogin>) =>
  getInstance().handleLogin(...args)) as HandleLogin;
export const handleLogout: HandleLogout = ((...args: Parameters<HandleLogout>) =>
  getInstance().handleLogout(...args)) as HandleLogout;
export const handleCallback: HandleCallback = ((...args: Parameters<HandleCallback>) =>
  getInstance().handleCallback(...args)) as HandleCallback;
export const handleProfile: HandleProfile = ((...args: Parameters<HandleProfile>) =>
  getInstance().handleProfile(...args)) as HandleProfile;
export const handleAuth: HandleAuth = (...args) => getInstance().handleAuth(...args);

export {
  UserProvider,
  UserProviderProps,
  UserProfile,
  UserContext,
  RequestError,
  useUser,
  WithPageAuthRequiredProps
} from './frontend';

export {
  AuthError,
  AccessTokenErrorCode,
  AccessTokenError,
  HandlerError,
  CallbackHandlerError,
  LoginHandlerError,
  LogoutHandlerError,
  ProfileHandlerError
} from './utils/errors';

export {
  MissingStateCookieError,
  MissingStateParamError,
  IdentityProviderError,
  ApplicationError
} from './auth0-session';

export {
  ConfigParameters,
  HandleAuth,
  HandleLogin,
  HandleProfile,
  HandleLogout,
  HandleCallback,
  ProfileOptions,
  Handlers,
  GetServerSidePropsResultWithSession,
  WithPageAuthRequiredOptions,
  PageRoute,
  WithApiAuthRequired,
  WithPageAuthRequired,
  SessionCache,
  GetSession,
  UpdateSession,
  GetAccessToken,
  Session,
  Claims,
  AccessTokenRequest,
  GetAccessTokenResult,
  CallbackOptions,
  AfterCallback,
  AfterRefetch,
  LoginOptions,
  LogoutOptions,
  GetLoginState,
  InitAuth0,
  OnError
};

export type SessionStore = GenericSessionStore<Session>;
/* c8 ignore stop */
