import { InitAuth0, SignInWithAuth0 } from './instance';
import { GetAccessToken, GetSession } from './session';
import { WithApiAuthRequired } from './helpers';
import { HandleAuth, HandleCallback, HandleLogin, HandleLogout, HandleProfile } from './handlers';
export {
  UserProvider,
  UserProviderProps,
  UserProfile,
  UserContext,
  useUser,
  withPageAuthRequired,
  WithPageAuthRequired
} from './frontend';

const instance: SignInWithAuth0 = {
  getSession() {
    throw new Error('The getSession method can only be used from the server side');
  },
  getAccessToken() {
    throw new Error('The getAccessToken method can only be used from the server side');
  },
  withApiAuthRequired() {
    throw new Error('The withApiAuthRequired method can only be used from the server side');
  },
  handleLogin() {
    throw new Error('The handleLogin method can only be used from the server side');
  },
  handleLogout() {
    throw new Error('The handleLogout method can only be used from the server side');
  },
  handleCallback() {
    throw new Error('The handleCallback method can only be used from the server side');
  },
  handleProfile() {
    throw new Error('The handleProfile method can only be used from the server side');
  },
  handleAuth() {
    throw new Error('The handleAuth method can only be used from the server side');
  },
  withPageAuthRequired() {
    throw new Error('The withPageAuthRequired method can only be used from the server side');
  }
};

export const initAuth0: InitAuth0 = () => instance;
export const getSession: GetSession = (...args) => instance.getSession(...args);
export const getAccessToken: GetAccessToken = (...args) => instance.getAccessToken(...args);
export const withApiAuthRequired: WithApiAuthRequired = (...args) => instance.withApiAuthRequired(...args);
export const handleLogin: HandleLogin = (...args) => instance.handleLogin(...args);
export const handleLogout: HandleLogout = (...args) => instance.handleLogout(...args);
export const handleCallback: HandleCallback = (...args) => instance.handleCallback(...args);
export const handleProfile: HandleProfile = (...args) => instance.handleProfile(...args);
export const handleAuth: HandleAuth = (...args) => instance.handleAuth(...args);
