import { getParams } from '../src/config';
import { ConfigParameters } from '../src';

const getParamsWithEnv = (env: any = {}, opts?: any): ConfigParameters => {
  const bkp = process.env;
  process.env = {
    ...process.env,
    ...{
      AUTH0_SECRET: undefined,
      AUTH0_ISSUER_BASE_URL: undefined,
      AUTH0_BASE_URL: undefined,
      AUTH0_CLIENT_ID: undefined,
      AUTH0_CLIENT_SECRET: undefined
    },
    ...env
  };
  try {
    return getParams(opts);
  } catch (e) {
    throw e;
  } finally {
    process.env = bkp;
  }
};

describe('config params', () => {
  test('should return an object from empty defaults', () => {
    expect(getParamsWithEnv()).toStrictEqual({
      auth0Logout: true,
      authorizationParams: {
        audience: undefined,
        response_type: 'code',
        scope: undefined
      },
      baseURL: undefined,
      clientID: undefined,
      clientSecret: undefined,
      clockTolerance: undefined,
      httpTimeout: undefined,
      enableTelemetry: undefined,
      idTokenSigningAlg: undefined,
      idpLogout: true,
      issuerBaseURL: undefined,
      legacySameSiteCookie: undefined,
      routes: {
        login: '/api/auth/login',
        postLoginRedirect: undefined,
        postLogoutRedirect: undefined,
        callback: '/api/auth/callback'
      },
      secret: undefined,
      session: {
        absoluteDuration: undefined,
        cookie: {
          domain: undefined,
          httpOnly: undefined,
          path: '/',
          sameSite: undefined,
          secure: undefined,
          transient: undefined
        },
        name: undefined,
        rolling: undefined,
        rollingDuration: undefined
      }
    });
  });

  test('should populate booleans', () => {
    expect(
      getParamsWithEnv({
        AUTH0_ENABLE_TELEMETRY: 'off',
        AUTH0_LEGACY_SAME_SITE_COOKIE: '0',
        AUTH0_IDP_LOGOUT: 'no',
        AUTH0_SESSION_ROLLING: false,
        AUTH0_COOKIE_TRANSIENT: true,
        AUTH0_COOKIE_HTTP_ONLY: 'on',
        AUTH0_COOKIE_SAME_SITE: 'yes',
        AUTH0_COOKIE_SECURE: 'ok',
        AUTH0_SESSION_ABSOLUTE_DURATION: 'yes'
      })
    ).toMatchObject({
      auth0Logout: false,
      enableTelemetry: false,
      idpLogout: false,
      legacySameSiteCookie: false,
      session: {
        rolling: false,
        absoluteDuration: true,
        cookie: {
          httpOnly: true,
          sameSite: true,
          secure: true,
          transient: true
        }
      }
    });
  });

  test('should populate numbers', () => {
    expect(
      getParamsWithEnv({
        AUTH0_CLOCK_TOLERANCE: '100',
        AUTH0_HTTP_TIMEOUT: '9999',
        AUTH0_SESSION_ROLLING_DURATION: '0',
        AUTH0_SESSION_ABSOLUTE_DURATION: '1'
      })
    ).toMatchObject({
      clockTolerance: 100,
      httpTimeout: 9999,
      session: {
        rolling: undefined,
        rollingDuration: 0,
        absoluteDuration: 1
      }
    });
  });

  test('passed in arguments should take precedence', () => {
    expect(
      getParamsWithEnv(
        {},
        {
          authorizationParams: {
            audience: 'foo',
            scope: 'bar'
          },
          baseURL: 'baz',
          routes: {
            callback: 'qux'
          },
          session: {
            absoluteDuration: 'quux',
            cookie: {
              transient: 'quuux'
            },
            name: 'quuuux'
          }
        }
      )
    ).toMatchObject({
      authorizationParams: {
        audience: 'foo',
        scope: 'bar'
      },
      baseURL: 'baz',
      routes: {
        callback: 'qux'
      },
      session: {
        absoluteDuration: 'quux',
        cookie: {
          transient: 'quuux'
        },
        name: 'quuuux'
      }
    });
  });

  test('should allow hostnames as baseURL', () => {
    expect(
      getParamsWithEnv({
        AUTH0_BASE_URL: 'foo.auth0.com'
      })
    ).toMatchObject({
      baseURL: 'https://foo.auth0.com'
    });
  });

  test('should accept optional callback path', () => {
    expect(
      getParamsWithEnv({
        AUTH0_CALLBACK: '/api/custom-callback'
      })
    ).toMatchObject({
      routes: expect.objectContaining({ callback: '/api/custom-callback' })
    });
  });
});
