/* eslint-disable */
import { ConfigParameters } from './auth0-session';
import Instance from './instance.browser';
import { SignInWithAuth0 } from './instance';

export { default as UserProvider, UserProfile, UserContext, useUser } from './hooks/use-user';

export function initAuth0(_config: ConfigParameters): SignInWithAuth0 {
  return Instance();
}
