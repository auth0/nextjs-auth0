export interface ICookieSessionStoreSettings {
  /**
   * Secret used to encrypt the cookie.
   */
  cookieSecret: string;

  /**
   * Name of the cookie in which the session will be stored.
   */
  cookieName?: string;

  /**
   * Cookie lifetime in seconds.
   * After this time has passed, the user will be redirect to Auth0 again.
   * Defaults to 8 hours.
   */
  cookieLifetime?: number;

  /**
   * Path on which to set the cookie.
   * Defaults to /
   */
  cookiePath?: string;

  /**
   * Save the id_token in the cookie.
   * Defaults to 'false'
   */
  storeIdToken?: boolean;

  /**
   * Save the access_token in the cookie.
   * Defaults to 'false'
   */
  storeAccessToken?: boolean;

  /**
   * Save the refresh_token in the cookie.
   * Defaults to 'false'
   */
  storeRefreshToken?: boolean;
}

export default class CookieSessionStoreSettings {
  readonly cookieSecret: string;

  readonly cookieName: string;

  readonly cookieLifetime: number;

  readonly cookiePath: string;

  readonly storeIdToken: boolean;

  readonly storeAccessToken: boolean;

  readonly storeRefreshToken: boolean;

  constructor(settings: ICookieSessionStoreSettings) {
    this.cookieSecret = settings.cookieSecret;
    if (!this.cookieSecret || !this.cookieSecret.length) {
      throw new Error('The cookieSecret setting is empty or null');
    }

    if (this.cookieSecret.length < 32) {
      throw new Error('The cookieSecret should be at least 32 characters long');
    }

    this.cookieName = settings.cookieName || 'a0:session';
    if (!this.cookieName || !this.cookieName.length) {
      throw new Error('The cookieName setting is empty or null');
    }

    this.cookieLifetime = settings.cookieLifetime || 60 * 60 * 8;

    this.cookiePath = settings.cookiePath || '/';
    if (!this.cookiePath || !this.cookiePath.length) {
      throw new Error('The cookiePath setting is empty or null');
    }

    this.storeIdToken = settings.storeIdToken || false;
    this.storeAccessToken = settings.storeAccessToken || false;
    this.storeRefreshToken = settings.storeRefreshToken || false;
  }
}
