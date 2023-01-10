import { IncomingMessage, ServerResponse } from 'http';
import { generators } from 'openid-client';
import { generateCookieValue, getCookieValue } from './utils/signed-cookies';
import { signing } from './utils/hkdf';
import NodeCookies from './utils/cookies';
import { Config } from './config';

export interface StoreOptions {
  sameSite?: boolean | 'lax' | 'strict' | 'none';
  value?: string;
}

export default class TransientStore {
  private keys?: Uint8Array[];

  constructor(private config: Config) {}

  private async getKeys(): Promise<Uint8Array[]> {
    if (!this.keys) {
      const secret = this.config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(signing));
    }
    return this.keys;
  }

  /**
   * Set a cookie with a value or a generated nonce.
   *
   * @param {String} key Cookie name to use.
   * @param {IncomingMessage} _req Server Request object.
   * @param {ServerResponse} res Server Response object.
   * @param {Object} opts Options object.
   * @param {String} opts.sameSite SameSite attribute of `None`, `Lax`, or `Strict`. Defaults to `None`.
   * @param {String} opts.value Cookie value. Omit this key to store a generated value.
   *
   * @return {String} Cookie value that was set.
   */
  async save(
    key: string,
    _req: IncomingMessage,
    res: ServerResponse,
    { sameSite = 'none', value = this.generateNonce() }: StoreOptions
  ): Promise<string> {
    const isSameSiteNone = sameSite === 'none';
    const { domain, path, secure } = this.config.session.cookie;
    const basicAttr = {
      httpOnly: true,
      secure,
      domain,
      path
    };
    const [signingKey] = await this.getKeys();
    const cookieSetter = new NodeCookies();

    {
      const cookieValue = await generateCookieValue(key, value, signingKey);
      // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
      cookieSetter.set(key, cookieValue, {
        ...basicAttr,
        sameSite,
        secure: isSameSiteNone ? true : basicAttr.secure
      });
    }

    if (isSameSiteNone && this.config.legacySameSiteCookie) {
      const cookieValue = await generateCookieValue(`_${key}`, value, signingKey);
      // Set the fallback cookie with no SameSite or Secure attributes.
      cookieSetter.set(`_${key}`, cookieValue, basicAttr);
    }

    cookieSetter.commit(res);
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
  async read(key: string, req: IncomingMessage, res: ServerResponse): Promise<string | undefined> {
    const cookies = new NodeCookies().getAll(req);
    const cookie = cookies[key];
    const cookieConfig = this.config.session.cookie;
    const cookieSetter = new NodeCookies();

    const verifyingKeys = await this.getKeys();
    let value = await getCookieValue(key, cookie, verifyingKeys);
    cookieSetter.clear(key, cookieConfig);

    if (this.config.legacySameSiteCookie) {
      const fallbackKey = `_${key}`;
      if (!value) {
        const fallbackCookie = cookies[fallbackKey];
        value = await getCookieValue(fallbackKey, fallbackCookie, verifyingKeys);
      }
      cookieSetter.clear(fallbackKey, cookieConfig);
    }

    cookieSetter.commit(res);
    return value;
  }

  /**
   * Generates a `nonce` value.
   *
   * @return {String}
   */
  generateNonce(): string {
    return generators.nonce();
  }

  /**
   * Generates a `code_verifier` value.
   *
   * @return {String}
   */
  generateCodeVerifier(): string {
    return generators.codeVerifier();
  }

  /**
   * Calculates a `code_challenge` value for a given `codeVerifier`.
   *
   * @param {String} codeVerifier Code verifier to calculate the `code_challenge` value from.
   * @return {String}
   */
  calculateCodeChallenge(codeVerifier: string): string {
    return generators.codeChallenge(codeVerifier);
  }
}
