import * as jose from 'jose';
import { TextDecoder } from 'util';

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 *
 * @return {string}
 */
export function encodeState(stateObject: { [key: string]: any }): string {
  // This filters out nonce, code_verifier, and max_age from the state object so that the values are
  // only stored in its dedicated transient cookie.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return jose.base64url.encode(JSON.stringify(filteredState));
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 *
 * @return {object|undefined}
 */
export function decodeState(stateValue?: string): { [key: string]: any } | undefined {
  try {
    return JSON.parse(new TextDecoder().decode(jose.base64url.decode(stateValue as string)));
  } catch (e) {
    return undefined;
  }
}
