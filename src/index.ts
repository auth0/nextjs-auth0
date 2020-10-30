/* eslint-disable */
import { ConfigParameters } from './auth0-session';
import { ISignInWithAuth0 } from './instance';

export { useUser, UserProfile, UserProvider } from './hooks/use-user';

export function initAuth0(settings: ConfigParameters): ISignInWithAuth0 {
  const isBrowser = typeof window !== 'undefined' || (process as any).browser;
  if (isBrowser) {
    return require('./instance.browser').default();
  }

  return require('./instance.node').default(settings);
}
