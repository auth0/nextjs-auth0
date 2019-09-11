import { ISession } from './session/session';
import { ISignInWithAuth0 } from './instance';

export default function createDummyBrowserInstance(): ISignInWithAuth0 & { isBrowser: boolean } {
  return {
    isBrowser: true,
    handleLogin: (): Promise<void> => {
      throw new Error('The handleLogin method can only be used from the server side');
    },
    handleLogout: (): Promise<void> => {
      throw new Error('The handleLogout method can only be used from the server side');
    },
    handleCallback: (): Promise<void> => {
      throw new Error('The handleCallback method can only be used from the server side');
    },
    handleProfile: (): Promise<void> => {
      throw new Error('The handleProfile method can only be used from the server side');
    },
    getSession: (): Promise<ISession | null | undefined> => {
      throw new Error('The getSession method can only be used from the server side');
    }
  };
}
