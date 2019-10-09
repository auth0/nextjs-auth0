/* eslint-disable */
import IAuth0Settings from './settings';
import Instance from './instance.browser';
import { ISignInWithAuth0 } from './instance';

// @ts-ignore un-used settings
export function initAuth0(settings: IAuth0Settings): ISignInWithAuth0 {
  return Instance();
}
