const hkdf = require('futoin-hkdf');

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const options = { hash: 'SHA-256' };

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
module.exports.encryption = (secret) =>
  hkdf(secret, BYTE_LENGTH, { info: ENCRYPTION_INFO, ...options });
module.exports.signing = (secret) =>
  hkdf(secret, BYTE_LENGTH, { info: SIGNING_INFO, ...options });
