import { BaseConfig, NextConfig, getConfig } from '../src/config';

const getConfigWithEnv = (env: any = {}, opts?: any): { baseConfig: BaseConfig; nextConfig: NextConfig } => {
  const bkp = process.env;
  process.env = {
    ...process.env,
    ...{
      AUTH0_SECRET: '__long_super_secret_secret__',
      AUTH0_ISSUER_BASE_URL: 'https://example.auth0.com',
      AUTH0_BASE_URL: 'https://example.com',
      AUTH0_CLIENT_ID: '__test_client_id__',
      AUTH0_CLIENT_SECRET: '__test_client_secret__'
    },
    ...env
  };
  try {
    return getConfig(opts);
  } catch (e) {
    throw e;
  } finally {
    process.env = bkp;
  }
};

describe('config params', () => {
  test('should return an object from empty defaults', () => {
    const { baseConfig, nextConfig } = getConfigWithEnv();
    expect(baseConfig).toStrictEqual({
      secret: '__long_super_secret_secret__',
      issuerBaseURL: 'https://example.auth0.com',
      baseURL: 'https://example.com',
      clientID: '__test_client_id__',
      clientSecret: '__test_client_secret__',
      clockTolerance: 60,
      httpTimeout: 5000,
      enableTelemetry: true,
      idpLogout: true,
      auth0Logout: true,
      idTokenSigningAlg: 'RS256',
      legacySameSiteCookie: true,
      authorizationParams: {
        response_type: 'code',
        audience: undefined,
        scope: 'openid profile email'
      },
      session: {
        name: 'appSession',
        rolling: true,
        rollingDuration: 86400,
        absoluteDuration: 604800,
        cookie: {
          domain: undefined,
          path: '/',
          transient: false,
          httpOnly: true,
          secure: true,
          sameSite: 'lax'
        }
      },
      routes: { callback: '/api/auth/callback', postLogoutRedirect: '' },
      getLoginState: expect.any(Function),
      identityClaimFilter: [
        'aud',
        'iss',
        'iat',
        'exp',
        'nbf',
        'nonce',
        'azp',
        'auth_time',
        's_hash',
        'at_hash',
        'c_hash'
      ],
      clientAuthMethod: 'client_secret_basic'
    });
    expect(nextConfig).toStrictEqual({
      identityClaimFilter: [
        'aud',
        'iss',
        'iat',
        'exp',
        'nbf',
        'nonce',
        'azp',
        'auth_time',
        's_hash',
        'at_hash',
        'c_hash'
      ],
      routes: {
        login: '/api/auth/login',
        callback: '/api/auth/callback',
        postLogoutRedirect: ''
      },
      organization: undefined
    });
  });

  test('should populate booleans', () => {
    expect(
      getConfigWithEnv({
        AUTH0_ENABLE_TELEMETRY: 'off',
        AUTH0_LEGACY_SAME_SITE_COOKIE: '0',
        AUTH0_IDP_LOGOUT: 'no',
        AUTH0_COOKIE_TRANSIENT: true,
        AUTH0_COOKIE_HTTP_ONLY: 'on',
        AUTH0_COOKIE_SAME_SITE: 'lax',
        AUTH0_COOKIE_SECURE: 'ok',
        AUTH0_SESSION_ABSOLUTE_DURATION: 'no'
      }).baseConfig
    ).toMatchObject({
      auth0Logout: false,
      enableTelemetry: false,
      idpLogout: false,
      legacySameSiteCookie: false,
      session: {
        absoluteDuration: false,
        cookie: {
          httpOnly: true,
          sameSite: 'lax',
          secure: true,
          transient: true
        }
      }
    });
    expect(
      getConfigWithEnv({
        AUTH0_SESSION_ROLLING_DURATION: 'no',
        AUTH0_SESSION_ROLLING: 'no'
      }).baseConfig
    ).toMatchObject({
      session: {
        rolling: false,
        rollingDuration: false
      }
    });
  });

  test('should populate numbers', () => {
    expect(
      getConfigWithEnv({
        AUTH0_CLOCK_TOLERANCE: '100',
        AUTH0_HTTP_TIMEOUT: '9999',
        AUTH0_SESSION_ROLLING_DURATION: '0',
        AUTH0_SESSION_ABSOLUTE_DURATION: '1'
      }).baseConfig
    ).toMatchObject({
      clockTolerance: 100,
      httpTimeout: 9999,
      session: {
        rolling: true,
        rollingDuration: 0,
        absoluteDuration: 1
      }
    });
  });

  test('passed in arguments should take precedence', () => {
    const { baseConfig, nextConfig } = getConfigWithEnv(
      {
        AUTH0_ORGANIZATION: 'foo'
      },
      {
        authorizationParams: {
          audience: 'foo',
          scope: 'openid bar'
        },
        baseURL: 'https://baz.com',
        routes: {
          callback: 'qux'
        },
        session: {
          absoluteDuration: 100,
          cookie: {
            transient: false
          },
          name: 'quuuux'
        },
        organization: 'bar'
      }
    );
    expect(baseConfig).toMatchObject({
      authorizationParams: {
        audience: 'foo',
        scope: 'openid bar'
      },
      baseURL: 'https://baz.com',
      routes: {
        callback: 'qux'
      },
      session: {
        absoluteDuration: 100,
        cookie: {
          transient: false
        },
        name: 'quuuux'
      }
    });
    expect(nextConfig).toMatchObject({
      organization: 'bar'
    });
  });

  test('should allow hostnames as baseURL', () => {
    expect(
      getConfigWithEnv({
        AUTH0_BASE_URL: 'foo.auth0.com'
      }).baseConfig
    ).toMatchObject({
      baseURL: 'https://foo.auth0.com'
    });
  });

  test('should accept optional callback path', () => {
    const { baseConfig, nextConfig } = getConfigWithEnv({
      AUTH0_CALLBACK: '/api/custom-callback'
    });
    expect(baseConfig).toMatchObject({
      routes: expect.objectContaining({ callback: '/api/custom-callback' })
    });
    expect(nextConfig).toMatchObject({
      routes: expect.objectContaining({ callback: '/api/custom-callback' })
    });
  });
});
