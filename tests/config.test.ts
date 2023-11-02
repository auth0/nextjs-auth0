import { NextConfig, getConfig } from '../src/config';

const getConfigWithEnv = (
  env: any = {},
  opts?: any,
  defaultEnv = {
    AUTH0_SECRET: '__long_super_secret_secret__',
    AUTH0_ISSUER_BASE_URL: 'https://example.auth0.com',
    AUTH0_BASE_URL: 'https://example.com',
    AUTH0_CLIENT_ID: '__test_client_id__',
    AUTH0_CLIENT_SECRET: '__test_client_secret__'
  }
): NextConfig => {
  const bkp = process.env;
  process.env = {
    ...process.env,
    ...defaultEnv,
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
    const nextConfig = getConfigWithEnv();
    expect(nextConfig).toStrictEqual({
      secret: '__long_super_secret_secret__',
      issuerBaseURL: 'https://example.auth0.com',
      baseURL: 'https://example.com',
      clientAssertionSigningAlg: undefined,
      clientAssertionSigningKey: undefined,
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
        autoSave: true,
        storeIDToken: true,
        cookie: {
          domain: undefined,
          path: '/',
          transient: false,
          httpOnly: true,
          secure: true,
          sameSite: 'lax'
        }
      },
      routes: { callback: '/api/auth/callback', postLogoutRedirect: '', login: '/api/auth/login' },
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
      clientAuthMethod: 'client_secret_basic',
      transactionCookie: {
        name: 'auth_verification',
        domain: undefined,
        path: '/',
        sameSite: 'lax',
        secure: true
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
        AUTH0_LOGOUT: 'false',
        AUTH0_COOKIE_TRANSIENT: true,
        AUTH0_COOKIE_HTTP_ONLY: 'on',
        AUTH0_COOKIE_SAME_SITE: 'lax',
        AUTH0_COOKIE_SECURE: 'ok',
        AUTH0_SESSION_ABSOLUTE_DURATION: 'no',
        AUTH0_SESSION_STORE_ID_TOKEN: '0'
      })
    ).toMatchObject({
      auth0Logout: false,
      enableTelemetry: false,
      idpLogout: false,
      legacySameSiteCookie: false,
      session: {
        absoluteDuration: false,
        storeIDToken: false,
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
      })
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
      })
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

  test('should populate arrays', () => {
    expect(
      getConfigWithEnv({
        AUTH0_IDENTITY_CLAIM_FILTER: 'claim1,claim2,claim3'
      })
    ).toMatchObject({
      identityClaimFilter: ['claim1', 'claim2', 'claim3']
    });
  });

  test('passed in arguments should take precedence', () => {
    const nextConfig = getConfigWithEnv(
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
          storeIDToken: false,
          cookie: {
            transient: false
          },
          name: 'quuuux'
        },
        organization: 'bar'
      }
    );
    expect(nextConfig).toMatchObject({
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
        storeIDToken: false,
        cookie: {
          transient: false
        },
        name: 'quuuux'
      },
      organization: 'bar'
    });
  });

  test('should allow hostnames as baseURL', () => {
    expect(
      getConfigWithEnv({
        AUTH0_BASE_URL: 'foo.auth0.com'
      })
    ).toMatchObject({
      baseURL: 'https://foo.auth0.com'
    });
  });

  test('should fallback to NEXT_PUBLIC_ prefixed base URL', () => {
    expect(
      getConfigWithEnv(
        {
          NEXT_PUBLIC_AUTH0_BASE_URL: 'public-foo.auth0.com'
        },
        undefined,
        {
          AUTH0_SECRET: '__long_super_secret_secret__',
          AUTH0_ISSUER_BASE_URL: 'https://example.auth0.com',
          AUTH0_BASE_URL: '',
          AUTH0_CLIENT_ID: '__test_client_id__',
          AUTH0_CLIENT_SECRET: '__test_client_secret__'
        }
      )
    ).toMatchObject({
      baseURL: 'https://public-foo.auth0.com'
    });
  });

  test('should prefer AUTH0_BASE_URL without the prefix', () => {
    expect(
      getConfigWithEnv({
        AUTH0_BASE_URL: 'foo.auth0.com',
        NEXT_PUBLIC_AUTH0_BASE_URL: 'bar.auth0.com'
      })
    ).toMatchObject({
      baseURL: 'https://foo.auth0.com'
    });
  });

  test('should accept optional callback path', () => {
    const nextConfig = getConfigWithEnv({
      AUTH0_CALLBACK: '/api/custom-callback'
    });
    expect(nextConfig).toMatchObject({
      routes: expect.objectContaining({ callback: '/api/custom-callback' })
    });
  });
});
