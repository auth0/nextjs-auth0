import { IncomingMessage } from 'http';
import { AuthorizationParameters as OidcAuthorizationParameters } from 'openid-client';
import { LoginOptions, DeepPartial } from './auth0-session';

/**
 * ## Configuration properties.
 *
 * The Server part of the SDK can be configured in 2 ways.
 *
 * ### 1. Environmental Variables
 *
 * The simplest way to use the SDK is to use the named exports ({@link HandleAuth}, {@link HandleLogin},
 * {@link HandleLogout}, {@link HandleCallback}, {@link HandleProfile}, {@link GetSession}, {@link GetAccessToken},
 * {@link WithApiAuthRequired} and {@link WithPageAuthRequired}), eg:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * return handleAuth();
 * ```
 *
 * When you use these named exports, an instance of the SDK is created for you which you can configure using
 * environmental variables:
 *
 * ### Required
 *
 * - `AUTH0_SECRET`: See {@link secret}
 * - `AUTH0_ISSUER_BASE_URL`: See {@link issuerBaseURL}
 * - `AUTH0_BASE_URL`: See {@link baseURL}
 * - `AUTH0_CLIENT_ID`: See {@link clientID}
 * - `AUTH0_CLIENT_SECRET`: See {@link clientSecret}
 *
 * ### Optional
 *
 * - `AUTH0_CLOCK_TOLERANCE`: See {@link clockTolerance}
 * - `AUTH0_ENABLE_TELEMETRY`: See {@link enableTelemetry}
 * - `AUTH0_IDP_LOGOUT`: See {@link idpLogout}
 * - `AUTH0_ID_TOKEN_SIGNING_ALG`: See {@link idTokenSigningAlg}
 * - `AUTH0_LEGACY_SAME_SITE_COOKIE`: See {@link legacySameSiteCookie}
 * - `AUTH0_POST_LOGOUT_REDIRECT`: See {@link Config.routes}
 * - `AUTH0_AUDIENCE`: See {@link Config.authorizationParams}
 * - `AUTH0_SCOPE`: See {@link Config.authorizationParams}
 * - `AUTH0_SESSION_NAME`: See {@link SessionConfig.name}
 * - `AUTH0_SESSION_ROLLING`: See {@link SessionConfig.rolling}
 * - `AUTH0_SESSION_ROLLING_DURATION`: See {@link SessionConfig.rollingDuration}
 * - `AUTH0_SESSION_ABSOLUTE_DURATION`: See {@link SessionConfig.absoluteDuration}
 * - `AUTH0_COOKIE_DOMAIN`: See {@link CookieConfig.domain}
 * - `AUTH0_COOKIE_PATH`: See {@link CookieConfig.path}
 * - `AUTH0_COOKIE_TRANSIENT`: See {@link CookieConfig.transient}
 * - `AUTH0_COOKIE_HTTP_ONLY`: See {@link CookieConfig.httpOnly}
 * - `AUTH0_COOKIE_SECURE`: See {@link CookieConfig.secure}
 * - `AUTH0_COOKIE_SAME_SITE`: See {@link CookieConfig.sameSite}
 *
 * ### 2. Create your own instance using {@link InitAuth0}
 *
 * If you don't want to configure the SDK with environment variables or you want more fine grained control over the
 * instance, you can create an instance yourself and use the handlers and helpers from that, eg:
 *
 * ```js
 * // utils/auth0.js
 * import { initAuth0 } from '@auth0/nextjs-auth0';
 *
 * export default initAuth0({ ...ConfigParameters... });
 *
 * // pages/api/auth/[...auth0].js
 * import auth0 from '../../../../utils/auth0';
 *
 * return auth0.handleAuth();
 * ```
 *
 * **Note** If you use {@link InitAuth0}, you should *not* use the other named exports as they will use a different
 * instance of the SDK.
 *
 * @category Server
 */
export interface Config {
  /**
   * The secret(s) used to derive an encryption key for the user identity in a session cookie and
   * to sign the transient cookies used by the login callback.
   * Use a single string key or array of keys for an encrypted session cookie.
   * Can use env key SECRET instead.
   */
  secret: string | Array<string>;

  /**
   * Object defining application session cookie attributes.
   */
  session: SessionConfig;

  /**
   * Boolean value to enable Auth0's logout feature.
   */
  auth0Logout: boolean;

  /**
   *  URL parameters used when redirecting users to the authorization server to log in.
   *
   *  If this property is not provided by your application, its default values will be:
   *
   * ```js
   * {
   *   response_type: 'code',
   *   scope: 'openid profile email'
   * }
   * ```
   *
   * New values can be passed in to change what is returned from the authorization server
   * depending on your specific scenario.
   *
   * Additional custom parameters can be added as well:
   *
   * ```js
   * {
   *   // Note: you need to provide required parameters if this object is set.
   *   response_type: 'code',
   *   scope: 'openid profile email',
   *   // Additional parameters
   *   acr_value: "tenant:test-tenant",
   *   custom_param: "custom-value"
   * };
   * ```
   */
  authorizationParams: AuthorizationParameters;

  /**
   * The root URL for the application router, eg https://localhost
   * Can use env key BASE_URL instead.
   * If you provide a domain, we will prefix it with `https://` - This can be useful when assigning it to
   * `VERCEL_URL` for preview deploys
   */
  baseURL: string;

  /**
   * The Client ID for your application.
   * Can be read from CLIENT_ID instead.
   */
  clientID: string;

  /**
   * The Client Secret for your application.
   * Required when requesting access tokens.
   * Can be read from CLIENT_SECRET instead.
   */
  clientSecret?: string;

  /**
   * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.`
   * Default is 60
   */
  clockTolerance: number;

  /**
   * To opt-out of sending the library and node version to your authorization server
   * via the `Auth0-Client` header. Default is `true
   */
  enableTelemetry: boolean;

  /**
   * @ignore
   */
  errorOnRequiredAuth: boolean;

  /**
   * @ignore
   */
  attemptSilentLogin: boolean;

  /**
   * Function that returns an object with URL-safe state values for `res.oidc.login()`.
   * Used for passing custom state parameters to your authorization server.
   * Can also be passed in to {@link HandleLogin}
   *
   * ```js
   * {
   *   ...
   *   getLoginState(req, options) {
   *     return {
   *       returnTo: options.returnTo || req.originalUrl,
   *       customState: 'foo'
   *     };
   *   }
   * }
   * ``
   */
  getLoginState: (req: IncomingMessage, options: LoginOptions) => Record<string, any>;

  /**
   * Array value of claims to remove from the ID token before storing the cookie session.
   * Default is `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash' ]`
   */
  identityClaimFilter: string[];

  /**
   * Boolean value to log the user out from the identity provider on application logout. Default is `true`
   */
  idpLogout: boolean;

  /**
   * String value for the expected ID token algorithm. Default is 'RS256'
   */
  idTokenSigningAlg: string;

  /**
   * REQUIRED. The root URL for the token issuer with no trailing slash.
   * This is `https://` plus your Auth0 domain
   * Can use env key ISSUER_BASE_URL instead.
   */
  issuerBaseURL: string;

  /**
   * Set a fallback cookie with no SameSite attribute when response_mode is form_post.
   * Default is true
   */
  legacySameSiteCookie: boolean;

  /**
   * @ignore
   */
  authRequired: boolean;

  /**
   * Boolean value to automatically install the login and logout routes.
   */
  routes: {
    /**
     * @ignore
     */
    login: string | false;

    /**
     * @ignore
     */
    logout: string | false;

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
}

/**
 * Configuration parameters used for the application session.
 *
 * @category Server
 */
export interface SessionConfig {
  /**
   * String value for the cookie name used for the internal session.
   * This value must only include letters, numbers, and underscores.
   * Default is `appSession`.
   */
  name: string;

  /**
   * If you want your session duration to be rolling, eg reset everytime the
   * user is active on your site, set this to a `true`. If you want the session
   * duration to be absolute, where the user is logged out a fixed time after login,
   * regardless of activity, set this to `false`
   * Default is `true`.
   */
  rolling: boolean;

  /**
   * Integer value, in seconds, for application session rolling duration.
   * The amount of time for which the user must be idle for then to be logged out.
   * Default is 86400 seconds (1 day).
   */
  rollingDuration: number;

  /**
   * Integer value, in seconds, for application absolute rolling duration.
   * The amount of time after the user has logged in that they will be logged out.
   * Set this to `false` if you don't want an absolute duration on your session.
   * Default is 604800 seconds (7 days).
   */
  absoluteDuration: boolean | number;

  cookie: CookieConfig;
}

/**
 * Configure how the session cookie and transient cookies are stored.
 *
 * @category Server
 */
export interface CookieConfig {
  /**
   * Domain name for the cookie.
   */
  domain?: string;

  /**
   * Path for the cookie.
   *
   * This defaults to `/`
   */
  path?: string;

  /**
   * Set to true to use a transient cookie (cookie without an explicit expiration).
   * Default is `false`
   */
  transient: boolean;

  /**
   * Flags the cookie to be accessible only by the web server.
   * Defaults to `true`.
   */
  httpOnly: boolean;

  /**
   * Marks the cookie to be used over secure channels only.
   * Defaults to the protocol of {@link Config.baseURL}.
   */
  secure?: boolean;

  /**
   * Value of the SameSite Set-Cookie attribute.
   * Defaults to "Lax" but will be adjusted based on {@link AuthorizationParameters.response_type}.
   */
  sameSite: boolean | 'lax' | 'strict' | 'none';
}

/**
 * Authorization parameters that will be passed to the identity provider on login.
 *
 * The library uses `response_mode: 'query'` and `response_type: 'code'` (with PKCE) by default.
 *
 * @category Server
 */
export interface AuthorizationParameters extends OidcAuthorizationParameters {
  scope: string;
  response_mode: 'query' | 'form_post';
  response_type: 'id_token' | 'code id_token' | 'code';
}

/**
 * See {@link Config}
 * @category Server
 */
export type ConfigParameters = DeepPartial<Config>;

/**
 * @ignore
 */
const FALSEY = ['n', 'no', 'false', '0', 'off'];

/**
 * @ignore
 */
const bool = (param?: any, defaultValue?: boolean): boolean | undefined => {
  if (param === undefined || param === '') return defaultValue;
  if (param && typeof param === 'string') return !FALSEY.includes(param.toLowerCase().trim());
  return !!param;
};

/**
 * @ignore
 */
const num = (param?: string): number | undefined => (param === undefined || param === '' ? undefined : +param);

/**
 * @ignore
 */
export const getParams = (params?: ConfigParameters): ConfigParameters => {
  const {
    AUTH0_SECRET,
    AUTH0_ISSUER_BASE_URL,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    AUTH0_CLOCK_TOLERANCE,
    AUTH0_ENABLE_TELEMETRY,
    AUTH0_IDP_LOGOUT,
    AUTH0_ID_TOKEN_SIGNING_ALG,
    AUTH0_LEGACY_SAME_SITE_COOKIE,
    AUTH0_POST_LOGOUT_REDIRECT,
    AUTH0_AUDIENCE,
    AUTH0_SCOPE,
    AUTH0_SESSION_NAME,
    AUTH0_SESSION_ROLLING,
    AUTH0_SESSION_ROLLING_DURATION,
    AUTH0_SESSION_ABSOLUTE_DURATION,
    AUTH0_COOKIE_DOMAIN,
    AUTH0_COOKIE_PATH,
    AUTH0_COOKIE_TRANSIENT,
    AUTH0_COOKIE_HTTP_ONLY,
    AUTH0_COOKIE_SECURE,
    AUTH0_COOKIE_SAME_SITE
  } = process.env;

  const baseURL =
    AUTH0_BASE_URL && !/^https?:\/\//.test(AUTH0_BASE_URL as string) ? `https://${AUTH0_BASE_URL}` : AUTH0_BASE_URL;

  return {
    secret: AUTH0_SECRET,
    issuerBaseURL: AUTH0_ISSUER_BASE_URL,
    baseURL: baseURL,
    clientID: AUTH0_CLIENT_ID,
    clientSecret: AUTH0_CLIENT_SECRET,
    clockTolerance: num(AUTH0_CLOCK_TOLERANCE),
    enableTelemetry: bool(AUTH0_ENABLE_TELEMETRY),
    idpLogout: bool(AUTH0_IDP_LOGOUT, true),
    auth0Logout: bool(AUTH0_IDP_LOGOUT, true),
    idTokenSigningAlg: AUTH0_ID_TOKEN_SIGNING_ALG,
    legacySameSiteCookie: bool(AUTH0_LEGACY_SAME_SITE_COOKIE),
    ...params,
    authorizationParams: {
      response_type: 'code',
      audience: AUTH0_AUDIENCE,
      scope: AUTH0_SCOPE,
      ...params?.authorizationParams
    },
    session: {
      name: AUTH0_SESSION_NAME,
      rolling: bool(AUTH0_SESSION_ROLLING),
      rollingDuration: num(AUTH0_SESSION_ROLLING_DURATION),
      absoluteDuration:
        AUTH0_SESSION_ABSOLUTE_DURATION && isNaN(Number(AUTH0_SESSION_ABSOLUTE_DURATION))
          ? bool(AUTH0_SESSION_ABSOLUTE_DURATION)
          : num(AUTH0_SESSION_ABSOLUTE_DURATION),
      ...params?.session,
      cookie: {
        domain: AUTH0_COOKIE_DOMAIN,
        path: AUTH0_COOKIE_PATH || '/',
        transient: bool(AUTH0_COOKIE_TRANSIENT),
        httpOnly: bool(AUTH0_COOKIE_HTTP_ONLY),
        secure: bool(AUTH0_COOKIE_SECURE),
        sameSite: bool(AUTH0_COOKIE_SAME_SITE),
        ...params?.session?.cookie
      }
    },
    routes: {
      callback: '/api/auth/callback',
      postLogoutRedirect: AUTH0_POST_LOGOUT_REDIRECT,
      ...params?.routes
    }
  };
};
