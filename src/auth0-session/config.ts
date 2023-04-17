import type { IncomingMessage } from 'http';
import type { AuthorizationParameters as OidcAuthorizationParameters, ClientAuthMethod } from 'openid-client';
import { SessionStore } from './session/stateful-session';

/**
 * Configuration properties.
 */
export interface Config {
  /**
   * The secret(s) used to derive an encryption key for the user identity in a session cookie and
   * to sign the transient cookies used by the login callback.
   * Use a single string key or array of keys for an encrypted session cookie.
   */
  secret: string | Array<string>;

  /**
   * Object defining application session cookie attributes.
   */
  session: SessionConfig;

  /**
   * Boolean value to enable Auth0's logout feature.
   */
  auth0Logout?: boolean;

  /**
   * URL parameters used when redirecting users to the authorization server to log in.
   *
   * If this property is not provided by your application, its default values will be:
   *
   * ```js
   * {
   *   response_type: 'id_token',
   *   response_mode: 'form_post',
   *   scope: 'openid profile email'
   * }
   * ```
   *
   * New values can be passed in to change what is returned from the authorization server
   * depending on your specific scenario.
   *
   * For example, to receive an access token for an API, you could initialize like the sample below.
   * Note that `response_mode` can be omitted because the OAuth2 default mode of `query` is fine:
   *
   * ```js
   * app.use(auth({
   *   authorizationParams: {
   *     response_type: 'code',
   *     scope: 'openid profile email read:reports',
   *     audience: 'https://your-auth0-api-identifier'
   *   }
   * }));
   * ```
   *
   * Additional custom parameters can be added as well:
   *
   * ```js
   * app.use(auth({
   *   authorizationParams: {
   *     // Note: you need to provide required parameters if this object is set
   *     response_type: 'id_token',
   *     response_mode: 'form_post',
   *     scope: 'openid profile email',
   *     // Additional parameters
   *     acr_value: 'tenant:test-tenant',
   *     custom_param: 'custom-value'
   *   }
   * }));
   * ```
   */
  authorizationParams: AuthorizationParameters;

  /**
   * The root URL for the application router, for example `https://localhost`.
   */
  baseURL: string;

  /**
   * The Client ID for your application.
   */
  clientID: string;

  /**
   * The Client Secret for your application.
   * Required when requesting access tokens.
   */
  clientSecret?: string;

  /**
   * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.`
   * Defaults to `60` seconds.
   */
  clockTolerance: number;

  /**
   * Integer value for the HTTP timeout in milliseconds for authentication requests.
   * Defaults to `5000` ms.
   */
  httpTimeout: number;

  /**
   * Boolean value to opt-out of sending the library and Node.js version to your authorization server
   * via the `Auth0-Client` header. Defaults to `true`.
   */
  enableTelemetry: boolean;

  /**
   * Function that returns an object with URL-safe state values for login.
   * Used for passing custom state parameters to your authorization server.
   *
   * ```js
   * app.use(auth({
   *   ...
   *   getLoginState(req, options) {
   *     return {
   *       returnTo: options.returnTo || req.originalUrl,
   *       customState: 'foo'
   *     };
   *   }
   * }));
   * ```
   */
  getLoginState: (req: IncomingMessage, options: LoginOptions) => Record<string, any>;

  /**
   * Array value of claims to remove from the ID token before storing the cookie session.
   * Defaults to `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash']`.
   */
  identityClaimFilter: string[];

  /**
   * Boolean value to log the user out from the identity provider on application logout. Defaults to `false`.
   */
  idpLogout: boolean;

  /**
   * String value for the expected ID token algorithm. Defaults to 'RS256'.
   */
  idTokenSigningAlg: string;

  /**
   * **REQUIRED** The root URL for the token issuer with no trailing slash.
   */
  issuerBaseURL: string;

  /**
   * Set a fallback cookie with no SameSite attribute when `response_mode` is `form_post`.
   * Defaults to `true`.
   */
  legacySameSiteCookie: boolean;

  routes: {
    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * This value must be registered on the authorization server.
     * The user will be redirected to this after a logout has been performed.
     */
    postLogoutRedirect: string;

    /**
     * Relative path to the application callback to process the response from the authorization server.
     */
    callback: string;
  };

  /**
   * The clients authentication method. Default is `none` when using response_type='id_token`,`private_key_jwt` when
   * using a `clientAssertionSigningKey`, otherwise `client_secret_basic`.
   */
  clientAuthMethod?: ClientAuthMethod;

  /**
   * Private key for use with `private_key_jwt` clients.
   * This should be a string that is the contents of a PEM file.
   * you can also use the `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable.
   */
  clientAssertionSigningKey?: string;

  /**
   * The algorithm used to sign the client assertion JWT.
   * Uses one of `token_endpoint_auth_signing_alg_values_supported` if not specified.
   * If the Authorization Server discovery document does not list `token_endpoint_auth_signing_alg_values_supported`
   * this property will be required.
   * You can also use the `AUTH0_CLIENT_ASSERTION_SIGNING_ALG` environment variable.
   */
  clientAssertionSigningAlg?: string;
}

/**
 * Configuration parameters used for the application session.
 */
export interface SessionConfig {
  /**
   * String value for the cookie name used for the internal session.
   * This value must only include letters, numbers, and underscores.
   * Defaults to `appSession`.
   */
  name: string;

  /**
   * By default, the session is stateless and stored in an encrypted cookie. But if you want a stateful session
   * you can provide a store with `get`, `set` and `destroy` methods to store the session on the server side.
   */
  store?: SessionStore<any>;

  /**
   * A function for generating a session id when using a custom session store.
   *
   * **IMPORTANT** You must use a suitably unique value to prevent collisions.
   */
  genId?: <Req = any, SessionType extends { [key: string]: any } = { [key: string]: any }>(
    req: Req,
    session: SessionType
  ) => string | Promise<string>;

  /**
   * If you want your session duration to be rolling, resetting everytime the
   * user is active on your site, set this to `true`. If you want the session
   * duration to be absolute, where the user gets logged out a fixed time after login
   * regardless of activity, set this to `false`.
   * Defaults to `true`.
   */
  rolling: boolean;

  /**
   * Integer value, in seconds, for application session rolling duration.
   * The amount of time for which the user must be idle for then to be logged out.
   * Should be `false` when rolling is `false`.
   * Defaults to `86400` seconds (1 day).
   */
  rollingDuration: number | false;

  /**
   * Integer value, in seconds, for application absolute rolling duration.
   * The amount of time after the user has logged in that they will be logged out.
   * Set this to `false` if you don't want an absolute duration on your session.
   * Defaults to `604800` seconds (7 days).
   */
  absoluteDuration: boolean | number;

  /**
   * Boolean value to enable automatic session saving when using rolling sessions.
   * If this is `false`, you must call `touchSession(req, res)` to update the session.
   * Defaults to `true`.
   */
  autoSave?: boolean;

  /**
   * Boolean value to store the ID token in the session. Storing it can make the session cookie too
   * large.
   * Defaults to `true`.
   */
  storeIDToken: boolean;

  cookie: CookieConfig;
}

export interface CookieConfig {
  /**
   * Domain name for the cookie.
   * Passed to the [response cookie](https://expressjs.com/en/api.html#res.cookie) as `domain`.
   */
  domain?: string;

  /**
   * Path for the cookie.
   * Passed to the [response cookie](https://expressjs.com/en/api.html#res.cookie) as `path`.
   */
  path?: string;

  /**
   * Set to `true` to use a transient cookie (cookie without an explicit expiration).
   * Defaults to `false`.
   */
  transient: boolean;

  /**
   * Flags the cookie to be accessible only by the web server.
   * Passed to the [response cookie](https://expressjs.com/en/api.html#res.cookie) as `httponly`.
   * Defaults to `true`.
   */
  httpOnly: boolean;

  /**
   * Marks the cookie to be used over secure channels only.
   * Passed to the [response cookie](https://expressjs.com/en/api.html#res.cookie) as `secure`.
   * Defaults to the protocol of {@link Config.baseURL}.
   */
  secure?: boolean;

  /**
   * Value of the SameSite `Set-Cookie` attribute.
   * Passed to the [response cookie](https://expressjs.com/en/api.html#res.cookie) as `samesite`.
   * Defaults to `Lax` but will be adjusted based on {@link AuthorizationParameters.response_type}.
   */
  sameSite: 'lax' | 'strict' | 'none';
}

export interface AuthorizationParameters extends OidcAuthorizationParameters {
  scope: string;
  response_mode: 'query' | 'form_post';
  response_type: 'id_token' | 'code id_token' | 'code';
}

export type GetLoginState = (req: any, options: LoginOptions) => { [key: string]: any };

/**
 * Custom options to pass to the login handler.
 */
export interface LoginOptions {
  /**
   * Override the default {@link Config.authorizationParams authorizationParams}.
   */
  authorizationParams?: Partial<AuthorizationParameters>;

  /**
   * URL to return to after login. Overrides the default in {@link Config.baseURL}.
   */
  returnTo?: string;

  /**
   * Generate a unique state value for use during login transactions.
   */
  getLoginState?: GetLoginState;
}

/**
 * Custom options to pass to the logout handler.
 */
export interface LogoutOptions {
  /**
   * URL to return to after logout. Overrides the
   * default in {@link Config.routes.postLogoutRedirect routes.postLogoutRedirect}.
   */
  returnTo?: string;

  /**
   * Additional custom parameters to pass to the logout endpoint.
   *
   * @example pass the federated logout param per https://auth0.com/docs/authenticate/login/logout/log-users-out-of-idps
   *
   * ```js
   * handleLogout(req, res, { logoutParams: { federated: '' } });
   * ```
   */
  logoutParams?: { [key: string]: any };
}
