import {
  StatelessSession,
  StatefulSession,
  TransientStore,
  loginHandler as baseLoginHandler,
  logoutHandler as baseLogoutHandler,
  callbackHandler as baseCallbackHandler,
  AbstractClient
} from './auth0-session';
import { handlerFactory, callbackHandler, loginHandler, logoutHandler, profileHandler } from './handlers';
import {
  sessionFactory,
  accessTokenFactory,
  SessionCache,
  Session,
  touchSessionFactory,
  updateSessionFactory
} from './session/';
import { withPageAuthRequiredFactory, withApiAuthRequiredFactory } from './helpers';
import { ConfigParameters, getConfig } from './config';
import { Auth0Server, telemetry } from './shared';
import withMiddlewareAuthRequiredFactory from './helpers/with-middleware-auth-required';

/**
 * Initialise your own instance of the SDK.
 *
 * See {@link ConfigParameters}.
 *
 * @category Server
 */
export type InitAuth0 = (params?: ConfigParameters) => Auth0Server;

export const _initAuth = ({
  params,
  genId,
  ClientCtor
}: {
  params?: ConfigParameters;
  genId: () => string;
  ClientCtor: new (...args: any[]) => AbstractClient;
}): Auth0Server => {
  // const lazy = (): Auth0Server => {
  const { baseConfig, nextConfig } = getConfig({ ...params, session: { genId, ...params?.session } });
  const client = new ClientCtor(baseConfig, telemetry);

  // Init base layer (with base config)
  const transientStore = new TransientStore(baseConfig);

  const sessionStore = baseConfig.session.store
    ? new StatefulSession<Session>(baseConfig)
    : new StatelessSession<Session>(baseConfig);
  const sessionCache = new SessionCache(baseConfig, sessionStore);
  const baseHandleLogin = baseLoginHandler(baseConfig, client, transientStore);
  const baseHandleLogout = baseLogoutHandler(baseConfig, client, sessionCache);
  const baseHandleCallback = baseCallbackHandler(baseConfig, client, sessionCache, transientStore);

  // Init Next layer (with next config)
  const getSession = sessionFactory(sessionCache);
  const touchSession = touchSessionFactory(sessionCache);
  const updateSession = updateSessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(nextConfig, client, sessionCache);
  const withApiAuthRequired = withApiAuthRequiredFactory(sessionCache);
  const withPageAuthRequired = withPageAuthRequiredFactory(nextConfig, sessionCache);
  const handleLogin = loginHandler(baseHandleLogin, nextConfig, baseConfig);
  const handleLogout = logoutHandler(baseHandleLogout);
  const handleCallback = callbackHandler(baseHandleCallback, nextConfig);
  const handleProfile = profileHandler(client, getAccessToken, sessionCache);
  const handleAuth = handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile });
  const withMiddlewareAuthRequired = withMiddlewareAuthRequiredFactory(nextConfig.routes, () => sessionCache);

  return {
    getSession,
    touchSession,
    updateSession,
    getAccessToken,
    withApiAuthRequired,
    withPageAuthRequired,
    handleLogin,
    handleLogout,
    handleCallback,
    handleProfile,
    handleAuth,
    withMiddlewareAuthRequired
  };
};
