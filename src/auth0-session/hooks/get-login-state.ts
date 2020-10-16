import base64url from 'base64url';
import createDebug from '../utils/debug';
import { IncomingMessage } from 'http';
import { LoginOptions } from '../config';

const debug = createDebug('get-login-state');

/**
 * Generate the state value for use during login transactions. It is used to store the intended
 * return URL after the user authenticates. State is not used to carry unique PRNG values here
 * because the library utilizes either nonce or PKCE for CSRF protection.
 *
 * @param {IncomingMessage} req
 * @param {LoginOptions} options
 *
 * @return {object}
 */
export function defaultState(req: IncomingMessage, options: LoginOptions) {
  const state = { returnTo: options.returnTo || req.url };
  debug('adding default state %O', state);
  return state;
}

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 *
 * @return {string}
 */
export function encodeState(stateObject: any = {}) {
  // this filters out nonce, code_verifier, and max_age from the state object so that the values are
  // only stored in its dedicated transient cookie
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject; // eslint-disable-line no-unused-vars
  return base64url.encode(JSON.stringify(filteredState));
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 *
 * @return {object}
 */
export function decodeState(stateValue: string) {
  return JSON.parse(base64url.decode(stateValue));
}
