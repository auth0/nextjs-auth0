import hkdf from '@panva/hkdf';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const digest = 'sha256';

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
export const encryption = (secret: string): Promise<Uint8Array> =>
  hkdf(digest, secret, '', ENCRYPTION_INFO, BYTE_LENGTH);
export const signing = (secret: string): Promise<Uint8Array> => hkdf(digest, secret, '', SIGNING_INFO, BYTE_LENGTH);
