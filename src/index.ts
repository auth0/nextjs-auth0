import { getConfig, CookieStore, TransientStore, clientFactory } from './auth0-session';
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
  AfterCallback
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
  Claims
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
import { getParams, Config, SessionConfig, CookieConfig, AuthorizationParameters, ConfigParameters } from './config';

/**
 * These instances are mutually exclusive. A user should get an error if they try to use a named export and
 * an instance method in the same app, eg:
 *
 * ```js
 * import auth0 from '../utils';
 * import { withApiAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export withApiAuthRequired(function MyApiRoute(req, res) {
 *   // `auth0.getSession` throws because you're already using the `withApiAuthRequired` named export
 *   // you should use the `getSession` named export instead.
 *   const session = await auth0.getSession(req, res);
 * });
 * ```
 */
let managedInstance: SignInWithAuth0;
let unmanagedInstance: SignInWithAuth0;

function assertOnlyInstance(otherInstance?: SignInWithAuth0) {
  if (otherInstance) {
    throw new Error(
      "You are creating multiple instances of the Auth0 SDK, this usually means you're mixing named imports and" +
        "auth0 instance methods or you're not resetting or mocking this module in your tests."
    );
  }
}

function getInstance(): SignInWithAuth0 {
  assertOnlyInstance(unmanagedInstance);
  if (managedInstance) {
    return managedInstance;
  }
  managedInstance = createInstance();
  return managedInstance;
}

const createInstance = (params?: ConfigParameters) => {
  const config = getConfig(getParams(params));
  const getClient = clientFactory(config, { name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(config);
  const cookieStore = new CookieStore(config);
  const sessionCache = new SessionCache(config, cookieStore);
  const getSession = sessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(getClient, config, sessionCache);
  const withApiAuthRequired = withApiAuthRequiredFactory(sessionCache);
  const withPageAuthRequired = withPageAuthRequiredFactory(getSession);
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

export const initAuth0: InitAuth0 = (params) => {
  assertOnlyInstance(managedInstance);
  unmanagedInstance = createInstance(params);
  return unmanagedInstance;
};
export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => getInstance().withApiAuthRequired(...args);
export const withPageAuthRequired: WithPageAuthRequired = (...args: any[]): any =>
  withPageAuthRequiredFactory(getSession)(...args);
export const handleLogin: HandleLogin = (...args) => getInstance().handleLogin(...args);
export const handleLogout: HandleLogout = (...args) => getInstance().handleLogout(...args);
export const handleCallback: HandleCallback = (...args) => getInstance().handleCallback(...args);
export const handleProfile: HandleProfile = (...args) => getInstance().handleProfile(...args);
export const handleAuth: HandleAuth = (...args) => getInstance().handleAuth(...args);

export { UserProvider, UserProviderProps, UserProfile, UserContext, useUser } from './frontend';

export {
  Config,
  SessionConfig,
  CookieConfig,
  AuthorizationParameters,
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
  GetAccessToken,
  Session,
  Claims,
  AccessTokenRequest,
  GetAccessTokenResult,
  CallbackOptions,
  AfterCallback,
  LoginOptions,
  LogoutOptions,
  GetLoginState
};
