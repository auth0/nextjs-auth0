const { JWK, JWE } = require('jose');

const { encryption: deriveKey } = require('../../lib/hkdf');
const epoch = () => (Date.now() / 1000) | 0;

const key = JWK.asKey(deriveKey('__test_secret__'));
const payload = JSON.stringify({ sub: '__test_sub__' });
const epochNow = epoch();
const weekInSeconds = 7 * 24 * 60 * 60;

const encryptOpts = {
  alg: 'dir',
  enc: 'A256GCM',
  uat: epochNow,
  iat: epochNow,
  exp: epochNow + weekInSeconds,
};

const jwe = JWE.encrypt(payload, key, encryptOpts);
const { cleartext } = JWE.decrypt(jwe, key, {
  complete: true,
  contentEncryptionAlgorithms: [encryptOpts.enc],
  keyManagementAlgorithms: [encryptOpts.alg],
});

module.exports = {
  encrypted: jwe,
  decrypted: cleartext,
};
