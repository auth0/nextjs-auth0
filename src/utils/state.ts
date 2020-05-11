import base64url from 'base64url';
import { randomBytes } from 'crypto';

/**
 * Create a state which can include custom data.
 * @param payload
 */
export function createState(payload?: Record<string, any>): string {
  const stateObject = payload || {};
  stateObject.nonce = createNonce();
  return encodeState(stateObject);
}

/**
 * Generates a nonce value.
 */
function createNonce(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Prepare a state object to send.
 */
function encodeState(stateObject: Record<string, any>): string {
  return base64url.encode(JSON.stringify(stateObject));
}

/**
 * Decode a state value. */
export function decodeState(stateValue: string): Record<string, any> {
  const decoded = base64url.decode(stateValue);

  // Backwards compatibility
  if (decoded.indexOf('{') !== 0) {
    return { nonce: stateValue };
  }

  return JSON.parse(base64url.decode(stateValue));
}
