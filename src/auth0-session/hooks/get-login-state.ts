import base64url from 'base64url';
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

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 *
 * @return {string}
 */
export function encodeState(stateObject: { [key: string]: any }): string {
  // this filters out nonce, code_verifier, and max_age from the state object so that the values are
  // only stored in its dedicated transient cookie
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return base64url.encode(JSON.stringify(filteredState));
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 *
 * @return {object}
 */
export function decodeState(stateValue: string): { [key: string]: any } {
  return JSON.parse(base64url.decode(stateValue));
}
