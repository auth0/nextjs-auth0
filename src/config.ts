import { AuthorizationParameters as OidcAuthorizationParameters } from 'openid-client';

import { DeepPartial, Config as SessionLayerConfig } from './auth0-session';

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
 * - `AUTH0_HTTP_TIMEOUT`: See {@link httpTimeout}
 * - `AUTH0_ENABLE_TELEMETRY`: See {@link enableTelemetry}
 * - `AUTH0_IDP_LOGOUT`: See {@link idpLogout}
 * - `AUTH0_ID_TOKEN_SIGNING_ALG`: See {@link idTokenSigningAlg}
 * - `AUTH0_LEGACY_SAME_SITE_COOKIE`: See {@link legacySameSiteCookie}
 * - `NEXT_PUBLIC_AUTH0_LOGIN`: See {@link Config.routes}
 * - `NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT`: See {@link Config.routes}
 * - `AUTH0_POST_LOGOUT_REDIRECT`: See {@link Config.routes}
 * - `AUTH0_CALLBACK`: See {@link Config.routes}
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
 * instance, you can create an instance yourself and use the handlers and helpers from that.
 *
 * First, export your configured instance from another module:
 *
 * ```js
 * // utils/auth0.js
 * import { initAuth0 } from '@auth0/nextjs-auth0';
 *
 * export default initAuth0({ ...ConfigParameters... });
 * ```
 *
 * Then import it into your route handler:
 *
 * ```js
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
export interface Config extends SessionLayerConfig {
  /**
   * Configuration parameters to override the default authentication URLs.
   */
  routes: {
    /**
     * Relative path to the login handler.
     */
    login: string;

    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * The user will be redirected to this after a login has been performed.
     */
    postLoginRedirect: string;

    /**
     * @ignore
     */
    logout: string;

    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * The user will be redirected to this after a logout has been performed.
     */
    postLogoutRedirect: string;

    /**
     * Relative path to the callback handler.
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
    AUTH0_HTTP_TIMEOUT,
    AUTH0_ENABLE_TELEMETRY,
    AUTH0_IDP_LOGOUT,
    AUTH0_ID_TOKEN_SIGNING_ALG,
    AUTH0_LEGACY_SAME_SITE_COOKIE,
    NEXT_PUBLIC_AUTH0_LOGIN,
    NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT,
    AUTH0_POST_LOGOUT_REDIRECT,
    AUTH0_CALLBACK,
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
    httpTimeout: num(AUTH0_HTTP_TIMEOUT),
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
      login: NEXT_PUBLIC_AUTH0_LOGIN || '/api/auth/login',
      postLoginRedirect: NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT,
      postLogoutRedirect: AUTH0_POST_LOGOUT_REDIRECT,
      callback: AUTH0_CALLBACK || '/api/auth/callback',
      ...params?.routes
    }
  };
};
