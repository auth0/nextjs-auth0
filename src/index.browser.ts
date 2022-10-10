import { InitAuth0, SignInWithAuth0 } from './instance';
import { GetAccessToken, GetSession } from './session';
import { WithApiAuthRequired } from './helpers';
import { HandleAuth, HandleCallback, HandleLogin, HandleLogout, HandleProfile } from './handlers';
export {
  UserProvider,
  UserProviderProps,
  UserProfile,
  UserContext,
  RequestError,
  useUser,
  withPageAuthRequired,
  WithPageAuthRequired
} from './frontend';

const serverSideOnly = (method: string): string => `The ${method} method can only be used from the server side`;

const instance: SignInWithAuth0 = {
  getSession() {
    throw new Error(serverSideOnly('getSession'));
  },
  updateSession() {
    throw new Error(serverSideOnly('updateSession'));
  },
  getAccessToken() {
    throw new Error(serverSideOnly('getAccessToken'));
  },
  withApiAuthRequired() {
    throw new Error(serverSideOnly('withApiAuthRequired'));
  },
  handleLogin() {
    throw new Error(serverSideOnly('handleLogin'));
  },
  handleLogout() {
    throw new Error(serverSideOnly('handleLogout'));
  },
  handleCallback() {
    throw new Error(serverSideOnly('handleCallback'));
  },
  handleProfile() {
    throw new Error(serverSideOnly('handleProfile'));
  },
  handleAuth() {
    throw new Error(serverSideOnly('handleAuth'));
  },
  withPageAuthRequired() {
    throw new Error(serverSideOnly('withPageAuthRequired'));
  }
};

export const initAuth0: InitAuth0 = () => instance;
export const getSession: GetSession = (...args) => instance.getSession(...args);
export const getAccessToken: GetAccessToken = (...args) => instance.getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => instance.withApiAuthRequired(...args);
export const handleLogin: HandleLogin = ((...args: Parameters<HandleLogin>) =>
  instance.handleLogin(...args)) as HandleLogin;
export const handleLogout: HandleLogout = ((...args: Parameters<HandleLogout>) =>
  instance.handleLogout(...args)) as HandleLogout;
export const handleCallback: HandleCallback = ((...args: Parameters<HandleCallback>) =>
  instance.handleCallback(...args)) as HandleCallback;
export const handleProfile: HandleProfile = ((...args: Parameters<HandleProfile>) =>
  instance.handleProfile(...args)) as HandleProfile;
export const handleAuth: HandleAuth = (...args) => instance.handleAuth(...args);
