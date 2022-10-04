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
  updateUser() {
    throw new Error(serverSideOnly('updateUser'));
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
export const handleLogout: HandleLogout = (...args) => instance.handleLogout(...args);
export const handleCallback: HandleCallback = (...args) => instance.handleCallback(...args);
export const handleProfile: HandleProfile = (...args) => instance.handleProfile(...args);
export const handleAuth: HandleAuth = (...args) => instance.handleAuth(...args);
