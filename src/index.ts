/* eslint-disable */
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';

export function initAuth0(settings: IAuth0Settings): ISignInWithAuth0 {
  const isBrowser = typeof window !== 'undefined' || (process as any).browser;
  if (isBrowser) {
    return require('./instance.browser').default(settings);
  }

  return require('./instance.node').default(settings);
}

/**
 * @deprecated useAuth0 has been deprecated in favor of initAuth0
 */
export const useAuth0 = initAuth0;
