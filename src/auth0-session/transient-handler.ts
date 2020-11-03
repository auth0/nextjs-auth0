import { IncomingMessage, ServerResponse } from 'http';
import { generators } from 'openid-client';
import { JWKS, JWS, JWK } from 'jose';
import { signing as deriveKey } from './utils/hkdf';
import { get as getCookie, clear as clearCookie, set as setCookie } from './utils/cookies';
import { Config, CookieConfig } from './config';

export interface StoreOptions {
  sameSite?: boolean | 'lax' | 'strict' | 'none';
  value?: string;
}

const header = { alg: 'HS256', b64: false, crit: ['b64'] };
const getPayload = (cookie: string, value: string): Buffer => Buffer.from(`${cookie}=${value}`);
const flattenedJWSFromCookie = (cookie: string, value: string, signature: string): JWS.FlattenedJWS => ({
  protected: Buffer.from(JSON.stringify(header))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_'),
  payload: getPayload(cookie, value),
  signature
});
const generateSignature = (cookie: string, value: string, key: JWK.Key): string => {
  const payload = getPayload(cookie, value);
  return JWS.sign.flattened(payload, key, header).signature;
};
const verifySignature = (cookie: string, value: string, signature: string, keystore: JWKS.KeyStore): boolean => {
  try {
    return !!JWS.verify(flattenedJWSFromCookie(cookie, value, signature), keystore, {
      algorithms: ['HS256'],
      crit: ['b64']
    });
  } catch (err) {
    return false;
  }
};
const getCookieValue = (cookie: string, value: string, keystore: JWKS.KeyStore): string | undefined => {
  if (!value) {
    return undefined;
  }
  let signature;
  [value, signature] = value.split('.');
  if (verifySignature(cookie, value, signature, keystore)) {
    return value;
  }

  return undefined;
};

const generateCookieValue = (cookie: string, value: string, key: JWK.Key): string => {
  const signature = generateSignature(cookie, value, key);
  return `${value}.${signature}`;
};

class TransientCookieHandler {
  private currentKey: JWK.Key | undefined;

  private keyStore: JWKS.KeyStore;

  private sessionCookieConfig: CookieConfig;

  private legacySameSiteCookie: boolean;

  constructor({ secret, session, legacySameSiteCookie }: Config) {
    let current;

    const secrets = Array.isArray(secret) ? secret : [secret];
    const keystore = new JWKS.KeyStore();
    secrets.forEach((secretString, i) => {
      const key = JWK.asKey(deriveKey(secretString));
      if (i === 0) {
        current = key;
      }
      keystore.add(key);
    });

    this.currentKey = current;
    this.keyStore = keystore;
    this.sessionCookieConfig = session.cookie;
    this.legacySameSiteCookie = legacySameSiteCookie;
  }

  /**
   * Set a cookie with a value or a generated nonce.
   *
   * @param {String} key Cookie name to use.
   * @param {IncomingMessage} req Server Request object.
   * @param {ServerResponse} res Server Response object.
   * @param {Object} opts Options object.
   * @param {String} opts.sameSite SameSite attribute of "None," "Lax," or "Strict". Default is "None."
   * @param {String} opts.value Cookie value. Omit this key to store a generated value.
   *
   * @return {String} Cookie value that was set.
   */
  store(
    key: string,
    req: IncomingMessage,
    res: ServerResponse,
    { sameSite = 'none', value = this.generateNonce() }: StoreOptions = {}
  ): string {
    const isSameSiteNone = sameSite === 'none';
    const { domain, path, secure } = this.sessionCookieConfig;
    const basicAttr = {
      httpOnly: true,
      secure: typeof secure === 'boolean' ? secure : req.url?.startsWith('https://'), // @TODO check
      domain,
      path
    };

    {
      const cookieValue = generateCookieValue(key, value, this.currentKey as JWK.Key);
      // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
      setCookie(res, key, cookieValue, {
        ...basicAttr,
        sameSite,
        secure: isSameSiteNone ? true : basicAttr.secure
      });
    }

    if (isSameSiteNone && this.legacySameSiteCookie) {
      const cookieValue = generateCookieValue(`_${key}`, value, this.currentKey as JWK.Key);
      // Set the fallback cookie with no SameSite or Secure attributes.
      setCookie(res, `_${key}`, cookieValue, basicAttr);
    }

    return value;
  }

  /**
   * Get a cookie value then delete it.
   *
   * @param {String} key Cookie name to use.
   * @param {IncomingMessage} req Express Request object.
   * @param {ServerResponse} res Express Response object.
   *
   * @return {String|undefined} Cookie value or undefined if cookie was not found.
   */
  getOnce(key: string, req: IncomingMessage, res: ServerResponse): string | undefined {
    const cookie = getCookie(req, key);
    const { domain, path } = this.sessionCookieConfig;

    let value = getCookieValue(key, cookie, this.keyStore);
    clearCookie(res, key, { domain, path });

    if (this.legacySameSiteCookie) {
      const fallbackKey = `_${key}`;
      if (!value) {
        const fallbackCookie = getCookie(req, fallbackKey);
        value = getCookieValue(fallbackKey, fallbackCookie, this.keyStore);
      }
      clearCookie(res, fallbackKey, { domain, path });
    }

    return value;
  }

  /**
   * Generates a nonce value.
   * @return {String}
   */
  generateNonce(): string {
    return generators.nonce();
  }

  /**
   * Generates a code_verifier value.
   * @return {String}
   */
  generateCodeVerifier(): string {
    return generators.codeVerifier();
  }

  /**
   * Calculates a code_challenge value for a given codeVerifier
   * @param {String} codeVerifier Code Verifier to calculate the code_challenge value from.
   * @return {String}
   */
  calculateCodeChallenge(codeVerifier: string): string {
    return generators.codeChallenge(codeVerifier);
  }
}

export default TransientCookieHandler;
