/* eslint-disable */
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';
import Instance from './instance.browser'

// @ts-ignore un-used settings
export function initAuth0(settings: IAuth0Settings): ISignInWithAuth0 {
  return Instance();
}
