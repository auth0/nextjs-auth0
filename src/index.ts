/* eslint-disable */
import { ConfigParameters } from './auth0-session';
import { SignInWithAuth0 } from './instance';

export { default as UserProvider, UserProfile, UserContext, useUser } from './hooks/use-user';

export function initAuth0(settings: ConfigParameters): SignInWithAuth0 {
  const isBrowser = typeof window !== 'undefined' || (process as any).browser;
  if (isBrowser) {
    return require('./instance.browser').default();
  }

  return require('./instance.node').default(settings);
}
