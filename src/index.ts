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
import version from './version';
import { getConfig, getLoginUrl, ConfigParameters } from './config';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';

/**
 * The SDK server instance.
 *
 * This is created for you when you use the named exports, or you can create your own using {@link InitAuth0}.
 *
 * See {@link ConfigParameters} for more info.
 *
 * @category Server
 */
export interface Auth0Server {
  /**
   * Session getter.
   */
  getSession: GetSession;

  /**
   * Append properties to the user.
   */
  updateSession: UpdateSession;

  /**
   * Access token getter.
   */
  getAccessToken: GetAccessToken;

  /**
   * Login handler which will redirect the user to Auth0.
   */
  handleLogin: HandleLogin;

  /**
   * Callback handler which will complete the transaction and create a local session.
   */
  handleCallback: HandleCallback;

  /**
   * Logout handler which will clear the local session and the Auth0 session.
   */
  handleLogout: HandleLogout;

  /**
   * Profile handler which return profile information about the user.
   */
  handleProfile: HandleProfile;

  /**
   * Helper that adds auth to an API route.
   */
  withApiAuthRequired: WithApiAuthRequired;

  /**
   * Helper that adds auth to a Page route.
   */
  withPageAuthRequired: WithPageAuthRequired;

  /**
   * Create the main handlers for your api routes.
   */
  handleAuth: HandleAuth;
}

/**
 * Initialise your own instance of the SDK.
 *
 * See {@link ConfigParameters}.
 *
 * @category Server
 */
export type InitAuth0 = (params?: ConfigParameters) => Auth0Server;

let instance: Auth0Server & { sessionCache: SessionCache };

// For using managed instance with named exports.
function getInstance(): Auth0Server & { sessionCache: SessionCache } {
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

export const _initAuth = (params?: ConfigParameters): Auth0Server & { sessionCache: SessionCache } => {
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
  OnError
};
/* c8 ignore stop */
