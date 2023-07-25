import {
  Auth0Server,
  ConfigParameters,
  GetAccessToken,
  GetSession,
  HandleAuth,
  HandleCallback,
  HandleLogin,
  HandleLogout,
  HandleProfile,
  SessionCache,
  UpdateSession,
  WithApiAuthRequired,
  WithPageAuthRequired,
  telemetry
} from './shared';
import { _initAuth } from './init';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';
import { getConfig, getLoginUrl } from './config';
import { withPageAuthRequiredFactory } from './helpers';
import { EdgeClient } from './auth0-session/client/edge-client';
import { WithMiddlewareAuthRequired } from './helpers/with-middleware-auth-required';

const genId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

let instance: Auth0Server & { sessionCache: SessionCache };

/**
 * Initialise your own instance of the SDK.
 *
 * See {@link ConfigParameters}.
 *
 * @category Server
 */
export type InitAuth0 = (params?: ConfigParameters) => Auth0Server;

// For using managed instance with named exports.
function getInstance(): Auth0Server & { sessionCache: SessionCache } {
  setIsUsingNamedExports();
  if (instance) {
    return instance;
  }
  const { baseConfig, nextConfig } = getConfig({ session: { genId } });
  const client = new EdgeClient(baseConfig, telemetry);
  instance = _initAuth({ baseConfig, nextConfig, client });
  return instance;
}

// For creating own instance.
export const initAuth0: InitAuth0 = (params) => {
  setIsUsingOwnInstance();
  const { baseConfig, nextConfig } = getConfig({ ...params, session: { genId, ...params?.session } });
  const client = new EdgeClient(baseConfig, telemetry);
  const { sessionCache, ...publicApi } = _initAuth({ baseConfig, nextConfig, client });
  return publicApi;
};

const getSessionCache = () => getInstance().sessionCache;
export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const updateSession: UpdateSession = (...args) => getInstance().updateSession(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) =>
  (getInstance().withApiAuthRequired as any)(...args);
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
export const withMiddlewareAuthRequired: WithMiddlewareAuthRequired = (...args) =>
  getInstance().withMiddlewareAuthRequired(...args);

export * from './shared';
