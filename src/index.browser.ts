/* eslint-disable */
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';

export function useAuth0(settings: IAuth0Settings): ISignInWithAuth0 {
  return require('./instance.browser').default(settings);
};
