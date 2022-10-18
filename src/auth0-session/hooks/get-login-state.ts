import createDebug from '../utils/debug';
import { GetLoginState } from '../config';

const debug = createDebug('get-login-state');

/**
 * Generate the state value for use during login transactions. It is used to store the intended
 * return URL after the user authenticates. State is not used to carry unique PRNG values here
 * because the library utilizes either nonce or PKCE for CSRF protection.
 *
 * @param {IncomingMessage} _req
 * @param {LoginOptions} options
 *
 * @return {object}
 */
export const getLoginState: GetLoginState = (_req, options) => {
  const state = { returnTo: options.returnTo };
  debug('adding default state %O', state);
  return state;
};
