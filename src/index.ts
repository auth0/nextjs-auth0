import crypto from 'crypto';
import {
  Auth0Server as Auth0ServerShared,
  ConfigParameters,
  GetAccessToken,
  GetSession,
  HandleAuth,
  HandleCallback,
  HandleLogin,
  HandleLogout,
  HandleProfile,
  TouchSession,
  UpdateSession,
  WithApiAuthRequired,
  WithPageAuthRequired
} from './shared';
import { _initAuth } from './init';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';
import { clientGetter } from './auth0-session/client/node-client';

const genId = () => crypto.randomBytes(16).toString('hex');

export type Auth0Server = Omit<Auth0ServerShared, 'withMiddlewareAuthRequired'>;

let instance: Auth0ServerShared;

/**
 * Initialise your own instance of the SDK.
 *
 * See {@link ConfigParameters}.
 *
 * @category Server
 */
export type InitAuth0 = (params?: ConfigParameters) => Omit<Auth0Server, 'withMiddlewareAuthRequired'>;

// For using managed instance with named exports.
function getInstance(): Auth0ServerShared {
  setIsUsingNamedExports();
  if (instance) {
    return instance;
  }
  instance = _initAuth({ genId, clientGetter });
  return instance;
}

// For creating own instance.
export const initAuth0: InitAuth0 = (params) => {
  setIsUsingOwnInstance();
  const { withMiddlewareAuthRequired, ...publicApi } = _initAuth({
    genId,
    params,
    clientGetter
  });
  return publicApi;
};

export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const updateSession: UpdateSession = (...args) => getInstance().updateSession(...args);
export const getAccessToken: GetAccessToken = (...args) => getInstance().getAccessToken(...args);
export const touchSession: TouchSession = (...args) => getInstance().touchSession(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) =>
  (getInstance().withApiAuthRequired as any)(...args);
export const withPageAuthRequired: WithPageAuthRequired = ((...args: Parameters<WithPageAuthRequired>) =>
  getInstance().withPageAuthRequired(...args)) as WithPageAuthRequired;
export const handleLogin: HandleLogin = ((...args: Parameters<HandleLogin>) =>
  getInstance().handleLogin(...args)) as HandleLogin;
export const handleLogout: HandleLogout = ((...args: Parameters<HandleLogout>) =>
  getInstance().handleLogout(...args)) as HandleLogout;
export const handleCallback: HandleCallback = ((...args: Parameters<HandleCallback>) =>
  getInstance().handleCallback(...args)) as HandleCallback;
export const handleProfile: HandleProfile = ((...args: Parameters<HandleProfile>) =>
  getInstance().handleProfile(...args)) as HandleProfile;
export const handleAuth: HandleAuth = (...args) => getInstance().handleAuth(...args);

export * from './shared';
