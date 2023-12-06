import type { Config as BaseConfig } from './auth0-session/config';
import { DeepPartial, get as getBaseConfig } from './auth0-session/get-config';
import type { Auth0Request, Auth0RequestCookies } from './auth0-session/http';

/**
 * @category server
 */
export interface NextConfig extends BaseConfig {
  /**
   * Log users in to a specific organization.
   *
   * This will specify an `organization` parameter in your user's login request and will add a step to validate
   * the `org_id` or `org_name` claim in your user's ID token.
   *
   * If your app supports multiple organizations, you should take a look at {@link AuthorizationParams.organization}.
   */
  organization?: string;
  routes: BaseConfig['routes'] & {
    login: string;
  };
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
 * - `AUTH0_SECRET`: See {@link BaseConfig.secret}.
 * - `AUTH0_ISSUER_BASE_URL`: See {@link BaseConfig.issuerBaseURL}.
 * - `AUTH0_BASE_URL`: See {@link BaseConfig.baseURL}.
 * - `AUTH0_CLIENT_ID`: See {@link BaseConfig.clientID}.
 * - `AUTH0_CLIENT_SECRET`: See {@link BaseConfig.clientSecret}.
 *
 * ### Optional
 *
 * - `AUTH0_CLOCK_TOLERANCE`: See {@link BaseConfig.clockTolerance}.
 * - `AUTH0_HTTP_TIMEOUT`: See {@link BaseConfig.httpTimeout}.
 * - `AUTH0_ENABLE_TELEMETRY`: See {@link BaseConfig.enableTelemetry}.
 * - `AUTH0_IDP_LOGOUT`: See {@link BaseConfig.idpLogout}.
 * - `AUTH0_ID_TOKEN_SIGNING_ALG`: See {@link BaseConfig.idTokenSigningAlg}.
 * - `AUTH0_LEGACY_SAME_SITE_COOKIE`: See {@link BaseConfig.legacySameSiteCookie}.
 * - `AUTH0_IDENTITY_CLAIM_FILTER`: See {@link BaseConfig.identityClaimFilter}.
 * - `AUTH0_PUSHED_AUTHORIZATION_REQUESTS` See {@link BaseConfig.pushedAuthorizationRequests}.
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
 * - `AUTH0_TRANSACTION_COOKIE_NAME` See {@link BaseConfig.transactionCookie}
 * - `AUTH0_TRANSACTION_COOKIE_DOMAIN` See {@link BaseConfig.transactionCookie}
 * - `AUTH0_TRANSACTION_COOKIE_PATH` See {@link BaseConfig.transactionCookie}
 * - `AUTH0_TRANSACTION_COOKIE_SAME_SITE` See {@link BaseConfig.transactionCookie}
 * - `AUTH0_TRANSACTION_COOKIE_SECURE` See {@link BaseConfig.transactionCookie}
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
 * export default auth0.handleAuth();
 * ```
 *
 * **IMPORTANT** If you use {@link InitAuth0}, you should *not* use the other named exports as they will use a different
 * instance of the SDK. Also note - this is for the server side part of the SDK - you will always use named exports for
 * the front end components: {@link UserProvider}, {@link UseUser} and the
 * front end version of {@link WithPageAuthRequired}
 *
 * @category Server
 */
export type ConfigParameters = DeepPartial<NextConfig>;

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
export const getConfig = (params: ConfigParameters = {}): NextConfig => {
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
  const AUTH0_PUSHED_AUTHORIZATION_REQUESTS = process.env.AUTH0_PUSHED_AUTHORIZATION_REQUESTS;
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
  const AUTH0_TRANSACTION_COOKIE_NAME = process.env.AUTH0_TRANSACTION_COOKIE_NAME;
  const AUTH0_TRANSACTION_COOKIE_DOMAIN = process.env.AUTH0_TRANSACTION_COOKIE_DOMAIN;
  const AUTH0_TRANSACTION_COOKIE_PATH = process.env.AUTH0_TRANSACTION_COOKIE_PATH;
  const AUTH0_TRANSACTION_COOKIE_SAME_SITE = process.env.AUTH0_TRANSACTION_COOKIE_SAME_SITE;
  const AUTH0_TRANSACTION_COOKIE_SECURE = process.env.AUTH0_TRANSACTION_COOKIE_SECURE;

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
    pushedAuthorizationRequests: bool(AUTH0_PUSHED_AUTHORIZATION_REQUESTS, false),
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
    clientAssertionSigningAlg: AUTH0_CLIENT_ASSERTION_SIGNING_ALG,
    transactionCookie: {
      name: AUTH0_TRANSACTION_COOKIE_NAME,
      domain: AUTH0_TRANSACTION_COOKIE_DOMAIN,
      path: AUTH0_TRANSACTION_COOKIE_PATH || '/',
      secure: bool(AUTH0_TRANSACTION_COOKIE_SECURE),
      sameSite: AUTH0_TRANSACTION_COOKIE_SAME_SITE as 'lax' | 'strict' | 'none' | undefined,
      ...baseParams.transactionCookie
    }
  });

  return {
    ...baseConfig,
    organization: organization || AUTH0_ORGANIZATION,
    routes: {
      ...baseConfig.routes,
      login: baseParams.routes?.login || process.env.NEXT_PUBLIC_AUTH0_LOGIN || '/api/auth/login'
    }
  };
};

export type GetConfig = (req: Auth0Request | Auth0RequestCookies) => Promise<NextConfig> | NextConfig;

export const configSingletonGetter = (params: ConfigParameters = {}, genId: () => string): GetConfig => {
  let config: NextConfig;
  return (req) => {
    if (!config) {
      // Bails out of static rendering for Server Components
      // Need to query cookies because Server Components don't have access to URL
      req.getCookies();
      if ('getUrl' in req) {
        // Bail out of static rendering for API Routes
        // Reading cookies is not always enough https://github.com/vercel/next.js/issues/49006
        req.getUrl();
      }
      config = getConfig({ ...params, session: { genId, ...params.session } });
    }
    return config;
  };
};
