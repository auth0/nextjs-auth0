import { ConfigParameters } from './auth0-session';

const FALSEY = ['n', 'no', 'false', '0', 'on', 'off'];

const bool = (param?: any, defaultValue?: boolean): boolean | undefined => {
  if (param === undefined || param === '') return defaultValue;
  if (param && typeof param === 'string') return !FALSEY.includes(param.toLowerCase().trim());
  return !!param;
};

const num = (param?: string): number | undefined => (param === undefined || param === '' ? undefined : +param);

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

  return {
    secret: AUTH0_SECRET,
    issuerBaseURL: AUTH0_ISSUER_BASE_URL,
    baseURL: AUTH0_BASE_URL,
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
