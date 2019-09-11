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
}
export default class CookieSessionStoreSettings {
    readonly cookieSecret: string;
    readonly cookieName: string;
    readonly cookieLifetime: number;
    readonly cookiePath: string;
    readonly storeIdToken: boolean;
    readonly storeAccessToken: boolean;
    constructor(settings: ICookieSessionStoreSettings);
}
