import { generateCookieValue, getCookieValue } from './utils/signed-cookies';
import { signing } from './utils/hkdf';
import { Config, GetConfig } from './config';
import { Auth0Request, Auth0RequestCookies, Auth0Response } from './http';

export interface StoreOptions {
  sameSite?: boolean | 'lax' | 'strict' | 'none';
  value: string;
}

export default class TransientStore {
  private keys?: Uint8Array[];

  protected getConfig: (req: Auth0RequestCookies) => Config | Promise<Config>;

  constructor(getConfig: GetConfig) {
    this.getConfig = typeof getConfig === 'function' ? getConfig : () => getConfig;
  }

  private async getKeys(config: Config): Promise<Uint8Array[]> {
    if (!this.keys) {
      const secret = config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(signing));
    }
    return this.keys;
  }

  /**
   * Set a cookie with a value or a generated nonce.
   *
   * @param {String} key Cookie name to use.
   * @param {IncomingMessage} req Server Request object.
   * @param {ServerResponse} res Server Response object.
   * @param {Object} opts Options object.
   * @param {String} opts.sameSite SameSite attribute of `None`, `Lax`, or `Strict`. Defaults to `None`.
   * @param {String} opts.value Cookie value. Omit this key to store a generated value.
   *
   * @return {String} Cookie value that was set.
   */
  async save(
    key: string,
    req: Auth0Request,
    res: Auth0Response,
    { sameSite = 'none', value }: StoreOptions
  ): Promise<string> {
    const isSameSiteNone = sameSite === 'none';
    const config = await this.getConfig(req);
    const { domain, path, secure } = config.transactionCookie;
    const basicAttr = {
      httpOnly: true,
      secure,
      domain,
      path
    };
    const [signingKey] = await this.getKeys(config);

    {
      const cookieValue = await generateCookieValue(key, value, signingKey);
      // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
      res.setCookie(key, cookieValue, {
        ...basicAttr,
        sameSite,
        secure: isSameSiteNone ? true : basicAttr.secure
      });
    }

    if (isSameSiteNone && config.legacySameSiteCookie) {
      const cookieValue = await generateCookieValue(`_${key}`, value, signingKey);
      // Set the fallback cookie with no SameSite or Secure attributes.
      res.setCookie(`_${key}`, cookieValue, basicAttr);
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
  async read(key: string, req: Auth0Request, res: Auth0Response): Promise<string | undefined> {
    const cookies = req.getCookies();
    const cookie = cookies[key];
    const config = await this.getConfig(req);
    const cookieConfig = config.transactionCookie;

    const verifyingKeys = await this.getKeys(config);
    let value = await getCookieValue(key, cookie, verifyingKeys);
    res.clearCookie(key, cookieConfig);

    if (config.legacySameSiteCookie) {
      const fallbackKey = `_${key}`;
      if (!value) {
        const fallbackCookie = cookies[fallbackKey];
        value = await getCookieValue(fallbackKey, fallbackCookie, verifyingKeys);
      }
      res.clearCookie(fallbackKey, cookieConfig);
    }

    return value;
  }
}
