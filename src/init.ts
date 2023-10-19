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

const __initAuth = ({
  genId,
  params,
  ClientCtor
}: {
  params?: ConfigParameters;
  genId: () => string;
  ClientCtor: new (...args: any[]) => AbstractClient;
}): Auth0Server & {
  sessionCache: SessionCache;
} => {
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
  const withPageAuthRequired = withPageAuthRequiredFactory(nextConfig.routes.login, () => sessionCache);
  const handleLogin = loginHandler(baseHandleLogin, nextConfig, baseConfig);
  const handleLogout = logoutHandler(baseHandleLogout);
  const handleCallback = callbackHandler(baseHandleCallback, nextConfig);
  const handleProfile = profileHandler(client, getAccessToken, sessionCache);
  const handleAuth = handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile });
  const withMiddlewareAuthRequired = withMiddlewareAuthRequiredFactory(nextConfig.routes, () => sessionCache);

  return {
    sessionCache,
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

export const _initAuth = (conf: {
  params?: ConfigParameters;
  genId: () => string;
  ClientCtor: any;
}): Auth0Server & {
  sessionCache: () => SessionCache;
} => {
  let instance: Auth0Server & {
    sessionCache: SessionCache;
  };

  const getInstance = (...args: any[]): any => {
    if (!instance) {
      instance = __initAuth(conf);
    }
    return instance;
  };

  return {
    sessionCache: () => getInstance().sessionCache,
    getSession: (...args: any[]) => getInstance(...args).getSession(...args),
    touchSession: (...args: any[]) => getInstance(...args).touchSession(...args),
    updateSession: (...args: any[]) => getInstance(...args).updateSession(...args),
    getAccessToken: (...args: any[]) => getInstance(...args).getAccessToken(...args),
    withApiAuthRequired:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).withApiAuthRequired(...args)(...reqArgs),
    withPageAuthRequired:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).withPageAuthRequired(...args)(...reqArgs),
    handleLogin:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).handleLogin(...args)(...reqArgs),
    handleLogout:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).handleLogout(...args)(...reqArgs),
    handleCallback:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).handleCallback(...args)(...reqArgs),
    handleProfile:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).handleProfile(...args)(...reqArgs),
    handleAuth:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).handleAuth(...args)(...reqArgs),
    withMiddlewareAuthRequired:
      (...args: any[]) =>
      (...reqArgs: any[]) =>
        getInstance(...args).withMiddlewareAuthRequired(...args)(...reqArgs)
  } as unknown as Auth0Server & { sessionCache: () => SessionCache };
};
