import {
  TransientStore,
  loginHandler as baseLoginHandler,
  logoutHandler as baseLogoutHandler,
  callbackHandler as baseCallbackHandler,
  Telemetry
} from './auth0-session';
import { handlerFactory, callbackHandler, loginHandler, logoutHandler, profileHandler } from './handlers';
import {
  sessionFactory,
  accessTokenFactory,
  SessionCache,
  touchSessionFactory,
  updateSessionFactory
} from './session/';
import { withPageAuthRequiredFactory, withApiAuthRequiredFactory } from './helpers';
import { configSingletonGetter, ConfigParameters } from './config';
import { Auth0Server, telemetry } from './shared';
import withMiddlewareAuthRequiredFactory from './helpers/with-middleware-auth-required';
import { GetClient } from './auth0-session/client/abstract-client';

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
  clientGetter
}: {
  params?: ConfigParameters;
  genId: () => string;
  clientGetter: (telemetry: Telemetry) => GetClient;
}): Auth0Server => {
  const getConfig = configSingletonGetter(params, genId);
  const getClient = clientGetter(telemetry);

  // Init base layer (with base config)
  const transientStore = new TransientStore(getConfig);

  const sessionCache = new SessionCache(getConfig);
  const baseHandleLogin = baseLoginHandler(getConfig, getClient, transientStore);
  const baseHandleLogout = baseLogoutHandler(getConfig, getClient, sessionCache);
  const baseHandleCallback = baseCallbackHandler(getConfig, getClient, sessionCache, transientStore);

  // Init Next layer (with next config)
  const getSession = sessionFactory(sessionCache);
  const touchSession = touchSessionFactory(sessionCache);
  const updateSession = updateSessionFactory(sessionCache);
  const getAccessToken = accessTokenFactory(getConfig, getClient, sessionCache);
  const withApiAuthRequired = withApiAuthRequiredFactory(sessionCache);
  const withPageAuthRequired = withPageAuthRequiredFactory(getConfig, sessionCache);
  const handleLogin = loginHandler(baseHandleLogin, getConfig);
  const handleLogout = logoutHandler(baseHandleLogout);
  const handleCallback = callbackHandler(baseHandleCallback, getConfig);
  const handleProfile = profileHandler(getConfig, getClient, getAccessToken, sessionCache);
  const handleAuth = handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile });
  const withMiddlewareAuthRequired = withMiddlewareAuthRequiredFactory(getConfig, sessionCache);

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
