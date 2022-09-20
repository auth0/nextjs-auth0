import {
  NodeCookies as Cookies,
  CookieStore,
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
  AfterRefetch
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
  updateUserFactory,
  UpdateUser
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

let instance: SignInWithAuth0 & { sessionCache: SessionCache };

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
  const { baseConfig, nextConfig } = getConfig(params);

  // Init base layer (with base config)
  const getClient = clientFactory(baseConfig, { name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(baseConfig);
  const cookieStore = new CookieStore(baseConfig, Cookies);
  const sessionCache = new SessionCache(baseConfig, cookieStore);
  const baseHandleLogin = baseLoginHandler(baseConfig, getClient, transientStore);
  const baseHandleLogout = baseLogoutHandler(baseConfig, getClient, sessionCache);
  const baseHandleCallback = baseCallbackHandler(baseConfig, getClient, sessionCache, transientStore);

  // Init Next layer (with next config)
  const getSession = sessionFactory(sessionCache);
  const updateUser = updateUserFactory(sessionCache);
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
    updateUser,
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
export const updateUser: UpdateUser = (...args) => getInstance().updateUser(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => getInstance().withApiAuthRequired(...args);
export const withPageAuthRequired: WithPageAuthRequired = withPageAuthRequiredFactory(getLoginUrl(), getSessionCache);
export const handleLogin: HandleLogin = (...args) => getInstance().handleLogin(...args);
export const handleLogout: HandleLogout = (...args) => getInstance().handleLogout(...args);
export const handleCallback: HandleCallback = (...args) => getInstance().handleCallback(...args);
export const handleProfile: HandleProfile = (...args) => getInstance().handleProfile(...args);
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
  UpdateUser,
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
  InitAuth0
};
/* c8 ignore stop */
