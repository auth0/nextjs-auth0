/* eslint-disable */
import { ConfigParameters } from './auth0-session';
import Instance from './instance.browser';
import { ISignInWithAuth0 } from './instance';

export { UserProvider, UserProfile, UserContext, useUser, withAuth } from './hooks';

// @ts-ignore un-used settings
export function initAuth0(config: ConfigParameters): ISignInWithAuth0 {
  return Instance();
}
