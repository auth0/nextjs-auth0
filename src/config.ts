import { IncomingMessage } from 'http';
import type { AuthorizationParameters as OidcAuthorizationParameters } from 'openid-client';
import type { LoginOptions } from './auth0-session/config';
import { SessionStore } from './auth0-session/session/stateful-session';
import Session from './session/session';
import { DeepPartial, get as getBaseConfig } from './auth0-session/get-config';

/**
 * @category server
 */
export interface BaseConfig {
  /**
   * The secret(s) used to derive an encryption key for the user identity in a session cookie and
   * to sign the transient cookies used by the login callback.
   * Provide a single string secret, but if you want to rotate the secret you can provide an array putting
   * the new secret first.
   * You can also use the `AUTH0_SECRET` environment variable.
   */
  secret: string | Array<string>;

  /**
   * Object defining application session cookie attributes.
   */
  session: SessionConfig;

  /**
   * Boolean value to enable Auth0's proprietary logout feature.
   * Since this SDK is for Auth0, it's set to `true` by default.
   * Set it to `false` if you don't want to use https://auth0.com/docs/api/authentication#logout.
   * You can also use the `AUTH0_LOGOUT` environment variable.
   */
  auth0Logout?: boolean;

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
   * depending on your specific scenario. Additional custom parameters can be added as well.
   *
   * **Note:** You must provide the required parameters if this object is set.
   *
   * ```js
   * {
   *   response_type: 'code',
   *   scope: 'openid profile email',
   *
   *   // Additional parameters
   *   acr_value: 'tenant:test-tenant',
   *   custom_param: 'custom-value'
   * };
   * ```
   */
  authorizationParams: AuthorizationParameters;

  /**
   * The root URL for the application router, for example `https://localhost`.
   * You can also use the `AUTH0_BASE_URL` environment variable.
   * If you provide a domain, we will prefix it with `https://`. This can be useful when assigning it to
   * `VERCEL_URL` for Vercel deploys.
   *
   * `NEXT_PUBLIC_AUTH0_BASE_URL` will also be checked if `AUTH0_BASE_URL` is not defined.
   */
  baseURL: string;

  /**
   * The Client ID for your application.
   * You can also use the `AUTH0_CLIENT_ID` environment variable.
   */
  clientID: string;

  /**
   * The Client Secret for your application.
   * Required when requesting access tokens.
   * You can also use the `AUTH0_CLIENT_SECRET` environment variable.
   */
  clientSecret?: string;

  /**
   * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.`
   * Defaults to `60` seconds.
   * You can also use the `AUTH0_CLOCK_TOLERANCE` environment variable.
   */
  clockTolerance: number;

  /**
   * Integer value for the HTTP timeout in milliseconds for authentication requests.
   * Defaults to `5000` ms.
   * You can also use the `AUTH0_HTTP_TIMEOUT` environment variable.
   */
  httpTimeout: number;

  /**
   * Boolean value to opt-out of sending the library and node version to your authorization server
   * via the `Auth0-Client` header. Defaults to `true`.
   * You can also use the `AUTH0_ENABLE_TELEMETRY` environment variable.
   */
  enableTelemetry: boolean;

  /**
   * Function that returns an object with URL-safe state values for login.
   * Used for passing custom state parameters to your authorization server.
   * Can also be passed in to {@link HandleLogin}.
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
   * ```
   */
  getLoginState: (req: IncomingMessage, options: LoginOptions) => Record<string, any>;

  /**
   * Array value of claims to remove from the ID token before storing the cookie session.
   * Defaults to `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash']`.
   * You can also use the `AUTH0_IDENTITY_CLAIM_FILTER` environment variable.
   */
  identityClaimFilter: string[];

  /**
   * Boolean value to log the user out from the identity provider on application logout. Defaults to `true`.
   * You can also use the `AUTH0_IDP_LOGOUT` environment variable.
   */
  idpLogout: boolean;

  /**
   * String value for the expected ID token algorithm. Defaults to 'RS256'.
   * You can also use the `AUTH0_ID_TOKEN_SIGNING_ALG` environment variable.
   */
  idTokenSigningAlg: string;

  /**
   * **REQUIRED** The root URL for the token issuer with no trailing slash.
   * This is `https://` plus your Auth0 domain.
   * You can also use the `AUTH0_ISSUER_BASE_URL` environment variable.
   */
  issuerBaseURL: string;

  /**
   * Set a fallback cookie with no `SameSite` attribute when `response_mode` is `form_post`.
   * The default `response_mode` for this SDK is `query` so this defaults to `false`
   * You can also use the `AUTH0_LEGACY_SAME_SITE_COOKIE` environment variable.
   */
  legacySameSiteCookie: boolean;

  /**
   * Boolean value to automatically install the login and logout routes.
   */
  routes: {
    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * This value must be registered on the authorization server.
     * The user will be redirected to this after a logout has been performed.
     * You can also use the `AUTH0_POST_LOGOUT_REDIRECT` environment variable.
     */
    postLogoutRedirect: string;

    /**
     * Relative path to the application callback to process the response from the authorization server.
     * Defaults to `/api/auth/callback`.
     * You can also use the `AUTH0_CALLBACK` environment variable.
     */
    callback: string;
  };

  /**
   * Private key for use with `private_key_jwt` clients.
   * This should be a string that is the contents of a PEM file.
   * You can also use the `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable.
   */
  clientAssertionSigningKey?: string;

  /**
   * The algorithm to sign the client assertion JWT.
   * Uses one of `token_endpoint_auth_signing_alg_values_supported` if not specified.
   * If the Authorization Server discovery document does not list `token_endpoint_auth_signing_alg_values_supported`
   * this property will be required.
   *  You can also use the `AUTH0_CLIENT_ASSERTION_SIGNING_ALG` environment variable.
   */
  clientAssertionSigningAlg?: string;
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
   * Defaults to `appSession`.
   * You can also use the `AUTH0_SESSION_NAME` environment variable.
   */
  name: string;

  /**
   * By default, the session is stateless and stored in an encrypted cookie. But if you want a stateful session
   * you can provide a store with `get`, `set` and `destroy` methods to store the session on the server.
   */
  store?: SessionStore<Session>;

  /**
   * A Function for generating a session id when using a custom session store.
   *
   * **IMPORTANT** If you override this, you must use a suitable value from your platform to
   * prevent collisions. For example, for Node: `require('crypto').randomBytes(16).toString('hex')`.
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
   * You can also use the `AUTH0_SESSION_ROLLING` environment variable.
   */
  rolling: boolean;

  /**
   * Integer value, in seconds, for application session rolling duration.
   * The amount of time for which the user must be idle for then to be logged out.
   * Should be `false` when rolling is `false`.
   * Defaults to `86400` seconds (1 day).
   * You can also use the AUTH0_SESSION_ROLLING_DURATION environment variable.
   */
  rollingDuration: number | false;

  /**
   * Integer value, in seconds, for application absolute rolling duration.
   * The amount of time after the user has logged in that they will be logged out.
   * Set this to `false` if you don't want an absolute duration on your session.
   * Defaults to `604800` seconds (7 days).
   * You can also use the `AUTH0_SESSION_ABSOLUTE_DURATION` environment variable.
   */
  absoluteDuration: boolean | number;

  /**
   * Boolean value to enable automatic session saving when using rolling sessions.
   * If this is `false`, you must call `touchSession(req, res)` to update the session.
   * Defaults to `true`.
   * You can also use the `AUTH0_SESSION_AUTO_SAVE` environment variable.
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

/**
 * Configure how the session cookie and transient cookies are stored.
 *
 * @category Server
 */
export interface CookieConfig {
  /**
   * Domain name for the cookie.
   * You can also use the `AUTH0_COOKIE_DOMAIN` environment variable.
   */
  domain?: string;

  /**
   * Path for the cookie.
   * Defaults to `/`.
   * You should change this to be more restrictive if you application shares a domain with other apps.
   * You can also use the `AUTH0_COOKIE_PATH` environment variable.
   */
  path?: string;

  /**
   * Set to `true` to use a transient cookie (cookie without an explicit expiration).
   * Defaults to `false`.
   * You can also use the `AUTH0_COOKIE_TRANSIENT` environment variable.
   */
  transient: boolean;

  /**
   * Flags the cookie to be accessible only by the web server.
   * Defaults to `true`.
   * You can also use the `AUTH0_COOKIE_HTTP_ONLY` environment variable.
   */
  httpOnly: boolean;

  /**
   * Marks the cookie to be used over secure channels only.
   * Defaults to the protocol of {@link BaseConfig.baseURL}.
   * You can also use the `AUTH0_COOKIE_SECURE` environment variable.
   */
  secure?: boolean;

  /**
   * Value of the SameSite `Set-Cookie` attribute.
   * Defaults to `lax` but will be adjusted based on {@link AuthorizationParameters.response_type}.
   * You can also use the `AUTH0_COOKIE_SAME_SITE` environment variable.
   */
  sameSite: 'lax' | 'strict' | 'none';
}

/**
 * Authorization parameters that will be passed to the identity provider on login.
 *
 * The library uses `response_mode: 'query'` and `response_type: 'code'` (with PKCE) by default.
 *
 * @category Server
 */
export interface AuthorizationParameters extends OidcAuthorizationParameters {
  /**
   * A space-separated list of scopes that will be requested during authentication. For example,
   * `openid profile email offline_access`.
   * Defaults to `openid profile email`.
   */
  scope: string;

  response_mode: 'query' | 'form_post';
  response_type: 'id_token' | 'code id_token' | 'code';
}

/**
 * @category server
 */
export interface NextConfig extends Pick<BaseConfig, 'identityClaimFilter'> {
  /**
   * Log users in to a specific organization.
   *
   * This will specify an `organization` parameter in your user's login request and will add a step to validate
   * the `org_id` or `org_name` claim in your user's ID token.
   *
   * If your app supports multiple organizations, you should take a look at {@link AuthorizationParams.organization}.
   */
  organization?: string;
  routes: {
    callback: string;
    login: string;
    unauthorized: string;
  };
  session: Pick<SessionConfig, 'storeIDToken'>;
}

/**
 * ## Configuration properties.
 *
 * The Server part of the SDK can be configured in 2 ways.
 *
 * ### 1. Environment Variables
 *
 * The simplest way to use the SDK is to use the named exports ({@link HandleAuth}, {@link HandleLogin},
 * {@link HandleLogout}, {@link HandleCallback}, {@link HandleProfile}, {@link GetSession}, {@link GetAccessToken},
 * {@link WithApiAuthRequired}, and {@link WithPageAuthRequired}).
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * return handleAuth();
 * ```
 *
 * When you use these named exports, an instance of the SDK is created for you which you can configure using
 * environment variables:
 *
 * ### Required
 *
 * - `AUTH0_SECRET`: See {@link secret}.
 * - `AUTH0_ISSUER_BASE_URL`: See {@link issuerBaseURL}.
 * - `AUTH0_BASE_URL`: See {@link baseURL}.
 * - `AUTH0_CLIENT_ID`: See {@link clientID}.
 * - `AUTH0_CLIENT_SECRET`: See {@link clientSecret}.
 *
 * ### Optional
 *
 * - `AUTH0_CLOCK_TOLERANCE`: See {@link clockTolerance}.
 * - `AUTH0_HTTP_TIMEOUT`: See {@link httpTimeout}.
 * - `AUTH0_ENABLE_TELEMETRY`: See {@link enableTelemetry}.
 * - `AUTH0_IDP_LOGOUT`: See {@link idpLogout}.
 * - `AUTH0_ID_TOKEN_SIGNING_ALG`: See {@link idTokenSigningAlg}.
 * - `AUTH0_LEGACY_SAME_SITE_COOKIE`: See {@link legacySameSiteCookie}.
 * - `AUTH0_IDENTITY_CLAIM_FILTER`: See {@link identityClaimFilter}.
 * - `NEXT_PUBLIC_AUTH0_LOGIN`: See {@link NextConfig.routes}.
 * - `AUTH0_CALLBACK`: See {@link BaseConfig.routes}.
 * - `AUTH0_POST_LOGOUT_REDIRECT`: See {@link BaseConfig.routes}.
 * - `AUTH0_AUDIENCE`: See {@link BaseConfig.authorizationParams}.
 * - `AUTH0_SCOPE`: See {@link BaseConfig.authorizationParams}.
 * - `AUTH0_ORGANIZATION`: See {@link NextConfig.organization}.
 * - `AUTH0_SESSION_NAME`: See {@link SessionConfig.name}.
 * - `AUTH0_SESSION_ROLLING`: See {@link SessionConfig.rolling}.
 * - `AUTH0_SESSION_ROLLING_DURATION`: See {@link SessionConfig.rollingDuration}.
 * - `AUTH0_SESSION_ABSOLUTE_DURATION`: See {@link SessionConfig.absoluteDuration}.
 * - `AUTH0_SESSION_AUTO_SAVE`: See {@link SessionConfig.autoSave}.
 * - `AUTH0_COOKIE_DOMAIN`: See {@link CookieConfig.domain}.
 * - `AUTH0_COOKIE_PATH`: See {@link CookieConfig.path}.
 * - `AUTH0_COOKIE_TRANSIENT`: See {@link CookieConfig.transient}.
 * - `AUTH0_COOKIE_HTTP_ONLY`: See {@link CookieConfig.httpOnly}.
 * - `AUTH0_COOKIE_SECURE`: See {@link CookieConfig.secure}.
 * - `AUTH0_COOKIE_SAME_SITE`: See {@link CookieConfig.sameSite}.
 * - `AUTH0_CLIENT_ASSERTION_SIGNING_KEY`: See {@link BaseConfig.clientAssertionSigningKey}
 * - `AUTH0_CLIENT_ASSERTION_SIGNING_ALG`: See {@link BaseConfig.clientAssertionSigningAlg}
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
 * // pages/api/auth/[auth0].js
 * import auth0 from '../../../../utils/auth0';
 *
 * return auth0.handleAuth();
 * ```
 *
 * **IMPORTANT** If you use {@link InitAuth0}, you should *not* use the other named exports as they will use a different
 * instance of the SDK. Also note - this is for the server side part of the SDK - you will always use named exports for
 * the front end components: {@Link UserProvider}, {@Link UseUser} and the
 * front end version of {@Link WithPageAuthRequired}
 *
 * @category Server
 */
export type ConfigParameters = DeepPartial<BaseConfig & NextConfig>;

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
const array = (param?: string): string[] | undefined =>
  param === undefined || param === '' ? undefined : param.replace(/\s/g, '').split(',');

/**
 * @ignore
 */
export const getLoginUrl = (): string => {
  return process.env.NEXT_PUBLIC_AUTH0_LOGIN || '/api/auth/login';
};

/**
 * @ignore
 */
export const getConfig = (params: ConfigParameters = {}): { baseConfig: BaseConfig; nextConfig: NextConfig } => {
  // Don't use destructuring here so that the `DefinePlugin` can replace any env vars specified in `next.config.js`
  const AUTH0_SECRET = process.env.AUTH0_SECRET;
  const AUTH0_ISSUER_BASE_URL = process.env.AUTH0_ISSUER_BASE_URL;
  const AUTH0_BASE_URL = process.env.AUTH0_BASE_URL || process.env.NEXT_PUBLIC_AUTH0_BASE_URL;
  const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
  const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
  const AUTH0_CLOCK_TOLERANCE = process.env.AUTH0_CLOCK_TOLERANCE;
  const AUTH0_HTTP_TIMEOUT = process.env.AUTH0_HTTP_TIMEOUT;
  const AUTH0_ENABLE_TELEMETRY = process.env.AUTH0_ENABLE_TELEMETRY;
  const AUTH0_IDP_LOGOUT = process.env.AUTH0_IDP_LOGOUT;
  const AUTH0_LOGOUT = process.env.AUTH0_LOGOUT;
  const AUTH0_ID_TOKEN_SIGNING_ALG = process.env.AUTH0_ID_TOKEN_SIGNING_ALG;
  const AUTH0_LEGACY_SAME_SITE_COOKIE = process.env.AUTH0_LEGACY_SAME_SITE_COOKIE;
  const AUTH0_IDENTITY_CLAIM_FILTER = process.env.AUTH0_IDENTITY_CLAIM_FILTER;
  const AUTH0_CALLBACK = process.env.AUTH0_CALLBACK;
  const AUTH0_POST_LOGOUT_REDIRECT = process.env.AUTH0_POST_LOGOUT_REDIRECT;
  const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
  const AUTH0_SCOPE = process.env.AUTH0_SCOPE;
  const AUTH0_ORGANIZATION = process.env.AUTH0_ORGANIZATION;
  const AUTH0_SESSION_NAME = process.env.AUTH0_SESSION_NAME;
  const AUTH0_SESSION_ROLLING = process.env.AUTH0_SESSION_ROLLING;
  const AUTH0_SESSION_ROLLING_DURATION = process.env.AUTH0_SESSION_ROLLING_DURATION;
  const AUTH0_SESSION_ABSOLUTE_DURATION = process.env.AUTH0_SESSION_ABSOLUTE_DURATION;
  const AUTH0_SESSION_AUTO_SAVE = process.env.AUTH0_SESSION_AUTO_SAVE;
  const AUTH0_SESSION_STORE_ID_TOKEN = process.env.AUTH0_SESSION_STORE_ID_TOKEN;
  const AUTH0_COOKIE_DOMAIN = process.env.AUTH0_COOKIE_DOMAIN;
  const AUTH0_COOKIE_PATH = process.env.AUTH0_COOKIE_PATH;
  const AUTH0_COOKIE_TRANSIENT = process.env.AUTH0_COOKIE_TRANSIENT;
  const AUTH0_COOKIE_HTTP_ONLY = process.env.AUTH0_COOKIE_HTTP_ONLY;
  const AUTH0_COOKIE_SECURE = process.env.AUTH0_COOKIE_SECURE;
  const AUTH0_COOKIE_SAME_SITE = process.env.AUTH0_COOKIE_SAME_SITE;
  const AUTH0_CLIENT_ASSERTION_SIGNING_KEY = process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY;
  const AUTH0_CLIENT_ASSERTION_SIGNING_ALG = process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG;

  const baseURL =
    AUTH0_BASE_URL && !/^https?:\/\//.test(AUTH0_BASE_URL as string) ? `https://${AUTH0_BASE_URL}` : AUTH0_BASE_URL;

  const { organization, ...baseParams } = params;

  const baseConfig = getBaseConfig({
    secret: AUTH0_SECRET,
    issuerBaseURL: AUTH0_ISSUER_BASE_URL,
    baseURL: baseURL,
    clientID: AUTH0_CLIENT_ID,
    clientSecret: AUTH0_CLIENT_SECRET,
    clockTolerance: num(AUTH0_CLOCK_TOLERANCE),
    httpTimeout: num(AUTH0_HTTP_TIMEOUT),
    enableTelemetry: bool(AUTH0_ENABLE_TELEMETRY),
    idpLogout: bool(AUTH0_IDP_LOGOUT, true),
    auth0Logout: bool(AUTH0_LOGOUT, true),
    idTokenSigningAlg: AUTH0_ID_TOKEN_SIGNING_ALG,
    legacySameSiteCookie: bool(AUTH0_LEGACY_SAME_SITE_COOKIE),
    identityClaimFilter: array(AUTH0_IDENTITY_CLAIM_FILTER),
    ...baseParams,
    authorizationParams: {
      response_type: 'code',
      audience: AUTH0_AUDIENCE,
      scope: AUTH0_SCOPE,
      ...baseParams.authorizationParams
    },
    session: {
      name: AUTH0_SESSION_NAME,
      rolling: bool(AUTH0_SESSION_ROLLING),
      rollingDuration:
        AUTH0_SESSION_ROLLING_DURATION && isNaN(Number(AUTH0_SESSION_ROLLING_DURATION))
          ? (bool(AUTH0_SESSION_ROLLING_DURATION) as false)
          : num(AUTH0_SESSION_ROLLING_DURATION),
      absoluteDuration:
        AUTH0_SESSION_ABSOLUTE_DURATION && isNaN(Number(AUTH0_SESSION_ABSOLUTE_DURATION))
          ? bool(AUTH0_SESSION_ABSOLUTE_DURATION)
          : num(AUTH0_SESSION_ABSOLUTE_DURATION),
      autoSave: bool(AUTH0_SESSION_AUTO_SAVE, true),
      storeIDToken: bool(AUTH0_SESSION_STORE_ID_TOKEN),
      ...baseParams.session,
      cookie: {
        domain: AUTH0_COOKIE_DOMAIN,
        path: AUTH0_COOKIE_PATH || '/',
        transient: bool(AUTH0_COOKIE_TRANSIENT),
        httpOnly: bool(AUTH0_COOKIE_HTTP_ONLY),
        secure: bool(AUTH0_COOKIE_SECURE),
        sameSite: AUTH0_COOKIE_SAME_SITE as 'lax' | 'strict' | 'none' | undefined,
        ...baseParams.session?.cookie
      }
    },
    routes: {
      callback: baseParams.routes?.callback || AUTH0_CALLBACK || '/api/auth/callback',
      postLogoutRedirect: baseParams.routes?.postLogoutRedirect || AUTH0_POST_LOGOUT_REDIRECT
    },
    clientAssertionSigningKey: AUTH0_CLIENT_ASSERTION_SIGNING_KEY,
    clientAssertionSigningAlg: AUTH0_CLIENT_ASSERTION_SIGNING_ALG
  });

  const nextConfig = {
    routes: {
      ...baseConfig.routes,
      login: baseParams.routes?.login || getLoginUrl(),
      unauthorized: baseParams.routes?.unauthorized || '/api/auth/401'
    },
    identityClaimFilter: baseConfig.identityClaimFilter,
    organization: organization || AUTH0_ORGANIZATION,
    session: { storeIDToken: baseConfig.session.storeIDToken }
  };

  return { baseConfig, nextConfig };
};
