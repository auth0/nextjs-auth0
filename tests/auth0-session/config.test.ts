import { Config, ConfigParameters, getConfig } from '../../src/auth0-session';
import { AuthorizationParameters } from '../../src/auth0-session/config';
import { DeepPartial } from '../../src/auth0-session/get-config';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org'
};

const validateAuthorizationParams = (authorizationParams: DeepPartial<AuthorizationParameters>): Config =>
  getConfig({ ...defaultConfig, authorizationParams });

describe('Config', () => {
  it('should get config for default config', () => {
    const config = getConfig(defaultConfig);
    expect(config).toMatchObject({
      authorizationParams: {
        response_type: 'id_token',
        response_mode: 'form_post',
        scope: 'openid profile email'
      }
    });
  });

  it('should get config for default config with environment variables', () => {
    const _env = process.env;
    process.env = {
      ...process.env,
      ISSUER_BASE_URL: defaultConfig.issuerBaseURL,
      CLIENT_ID: defaultConfig.clientID,
      SECRET: defaultConfig.secret,
      BASE_URL: defaultConfig.baseURL
    };
    const config = getConfig();
    expect(config).toMatchObject({
      issuerBaseURL: defaultConfig.issuerBaseURL,
      authorizationParams: {
        response_type: 'id_token',
        response_mode: 'form_post',
        scope: 'openid profile email'
      }
    });
    process.env = _env;
  });

  it('should get config for response_type=code', () => {
    const config = getConfig({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code'
      }
    });
    expect(config).toMatchObject({
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email'
      }
    });
  });

  it('should require a fully qualified URL for issuer', () => {
    const config = {
      ...defaultConfig,
      issuerBaseURL: 'www.example.com'
    };
    expect(() => getConfig(config)).toThrowError(new TypeError('"issuerBaseURL" must be a valid uri'));
  });

  it('should set idpLogout to true when auth0Logout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      auth0Logout: true
    });
    expect(config).toMatchObject({
      auth0Logout: true,
      idpLogout: true
    });
  });

  it('auth0Logout and idpLogout should default to false', () => {
    const config = getConfig(defaultConfig);
    expect(config).toMatchObject({
      auth0Logout: false,
      idpLogout: false
    });
  });

  it('should not set auth0Logout to true when idpLogout is true', () => {
    const config = getConfig({
      ...defaultConfig,
      idpLogout: true
    });
    expect(config).toMatchObject({
      auth0Logout: false,
      idpLogout: true
    });
  });

  it('should set default route paths', () => {
    const config = getConfig(defaultConfig);
    expect(config.routes).toMatchObject({
      callback: '/callback',
      login: '/login',
      logout: '/logout'
    });
  });

  it('should set custom route paths', () => {
    const config = getConfig({
      ...defaultConfig,
      routes: {
        callback: '/custom-callback',
        login: '/custom-login',
        logout: '/custom-logout'
      }
    });
    expect(config.routes).toMatchObject({
      callback: '/custom-callback',
      login: '/custom-login',
      logout: '/custom-logout'
    });
  });

  it('should set default app session configuration', () => {
    const config = getConfig(defaultConfig);
    expect(config.session).toMatchObject({
      rollingDuration: 86400,
      name: 'appSession',
      cookie: {
        sameSite: 'lax',
        httpOnly: true,
        transient: false
      }
    });
  });

  it('should set custom cookie configuration', () => {
    const config = getConfig({
      ...defaultConfig,
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'strict'
        }
      }
    });
    expect(config).toMatchObject({
      secret: ['__test_session_secret_1__', '__test_session_secret_2__'],
      session: {
        name: '__test_custom_session_name__',
        rollingDuration: 1234567890,
        absoluteDuration: 604800,
        rolling: true,
        cookie: {
          domain: '__test_custom_domain__',
          transient: true,
          httpOnly: false,
          secure: true,
          sameSite: 'strict'
        }
      }
    });
  });

  it('should fail when the baseURL is invalid', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        baseURL: '__invalid_url__'
      })
    ).toThrowError('"baseURL" must be a valid uri');
  });

  it('should fail when the clientID is not provided', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        clientID: undefined
      })
    ).toThrowError('"clientID" is required');
  });

  it('should fail when the baseURL is not provided', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        baseURL: undefined
      })
    ).toThrowError('"baseURL" is required');
  });

  it('should fail when the secret is not provided', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        secret: undefined
      })
    ).toThrowError('"secret" is required');
  });

  it('should fail when app session length is not an integer', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        session: {
          rollingDuration: 3.14159
        }
      })
    ).toThrow('"session.rollingDuration" must be an integer');
  });

  it('should fail when rollingDuration is defined and rolling is false', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          rollingDuration: 100
        }
      })
    ).toThrow('"session.rollingDuration" must be false when "session.rolling" is disabled');
  });

  it('should fail when rollingDuration is not defined and rolling is true', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        session: {
          rolling: true,
          rollingDuration: (false as unknown) as undefined // testing invalid configuration
        }
      })
    ).toThrow('"session.rollingDuration" must be provided an integer value when "session.rolling" is true');
  });

  it('should fail when absoluteDuration is not defined and rolling is false', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        session: {
          rolling: false,
          absoluteDuration: false
        }
      })
    ).toThrowError('"session.absoluteDuration" must be provided an integer value when "session.rolling" is false');
  });

  it('should fail when app session secret is invalid', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        secret: ({ key: '__test_session_secret__' } as unknown) as string // testing invalid configuration
      })
    ).toThrow('"secret" must be one of [string, binary, array]');
  });

  it('should fail when app session cookie httpOnly is not a boolean', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        session: {
          cookie: {
            httpOnly: ('__invalid_httponly__' as unknown) as boolean // testing invalid configuration
          }
        }
      })
    ).toThrowError('"session.cookie.httpOnly" must be a boolean');
  });

  it('should fail when app session cookie secure is not a boolean', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            secure: ('__invalid_secure__' as unknown) as boolean // testing invalid configuration
          }
        }
      })
    ).toThrowError('"session.cookie.secure" must be a boolean');
  });

  it('should fail when app session cookie sameSite is invalid', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            sameSite: ('__invalid_samesite__' as unknown) as boolean // testing invalid configuration
          }
        }
      })
    ).toThrowError('"session.cookie.sameSite" must be one of [lax, strict, none]');
  });

  it('should fail when app session cookie domain is invalid', function () {
    expect(() =>
      getConfig({
        ...defaultConfig,
        secret: '__test_session_secret__',
        session: {
          cookie: {
            domain: (false as unknown) as string // testing invalid configuration
          }
        }
      })
    ).toThrowError('"session.cookie.domain" must be a string');
  });

  it("shouldn't allow a secret of less than 8 chars", () => {
    expect(() => getConfig({ ...defaultConfig, secret: 'short' })).toThrowError(
      new TypeError('"secret" does not match any of the allowed types')
    );
    expect(() => getConfig({ ...defaultConfig, secret: ['short', 'too'] })).toThrowError(
      new TypeError('"secret[0]" does not match any of the allowed types')
    );
    expect(() => getConfig({ ...defaultConfig, secret: Buffer.from('short').toString() })).toThrowError(
      new TypeError('"secret" does not match any of the allowed types')
    );
  });

  it("shouldn't allow code flow without clientSecret", () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        authorizationParams: {
          response_type: 'code'
        }
      })
    ).toThrowError(new TypeError('"clientSecret" is required for a response_type that includes code'));
  });

  it("shouldn't allow hybrid flow without clientSecret", () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        authorizationParams: {
          response_type: 'code id_token'
        }
      })
    ).toThrowError(new TypeError('"clientSecret" is required for a response_type that includes code'));
  });

  it('should not allow "none" for idTokenSigningAlg', () => {
    const config = (idTokenSigningAlg: string) => (): Config =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg
      });
    const expected = '"idTokenSigningAlg" contains an invalid value';
    expect(config('none')).toThrowError(new TypeError(expected));
    expect(config('NONE')).toThrowError(new TypeError(expected));
    expect(config('noNE')).toThrowError(new TypeError(expected));
  });

  it('should require clientSecret for ID tokens with HMAC based algorithms', () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg: 'HS256',
        authorizationParams: {
          response_type: 'id_token'
        }
      })
    ).toThrowError(new TypeError('"clientSecret" is required for ID tokens with HMAC based algorithms'));
  });

  it('should require clientSecret for ID tokens in hybrid flow with HMAC based algorithms', () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg: 'HS256',
        authorizationParams: {
          response_type: 'code id_token'
        }
      })
    ).toThrowError(new TypeError('"clientSecret" is required for ID tokens with HMAC based algorithms'));
  });

  it('should require clientSecret for ID tokens in code flow with HMAC based algorithms', () => {
    expect(() =>
      getConfig({
        ...defaultConfig,
        idTokenSigningAlg: 'HS256',
        authorizationParams: {
          response_type: 'code'
        }
      })
    ).toThrowError(new TypeError('"clientSecret" is required for ID tokens with HMAC based algorithms'));
  });

  it('should allow empty auth params', () => {
    expect(validateAuthorizationParams).not.toThrow();
    expect(() => validateAuthorizationParams({})).not.toThrow();
  });

  it('should not allow empty scope', () => {
    expect(() => validateAuthorizationParams({ scope: (null as unknown) as undefined })).toThrowError(
      new TypeError('"authorizationParams.scope" must be a string')
    );
    expect(() => validateAuthorizationParams({ scope: '' })).toThrowError(
      new TypeError('"authorizationParams.scope" is not allowed to be empty')
    );
  });

  it('should not allow scope without openid', () => {
    expect(() => validateAuthorizationParams({ scope: 'profile email' })).toThrowError(
      new TypeError('"authorizationParams.scope" with value "profile email" fails to match the contains openid pattern')
    );
  });

  it('should allow scope with openid', () => {
    expect(() => validateAuthorizationParams({ scope: 'openid read:users' })).not.toThrow();
    expect(() => validateAuthorizationParams({ scope: 'read:users openid' })).not.toThrow();
    expect(() => validateAuthorizationParams({ scope: 'read:users openid profile email' })).not.toThrow();
  });

  it('should not allow empty response_type', () => {
    expect(() => validateAuthorizationParams({ response_type: (null as unknown) as undefined })).toThrowError(
      new TypeError('"authorizationParams.response_type" must be one of [id_token, code id_token, code]')
    );
    expect(() => validateAuthorizationParams({ response_type: ('' as unknown) as undefined })).toThrowError(
      new TypeError('"authorizationParams.response_type" must be one of [id_token, code id_token, code]')
    );
  });

  it('should not allow invalid response_types', () => {
    expect(() => validateAuthorizationParams({ response_type: 'foo' as 'code' })).toThrowError(
      new TypeError('"authorizationParams.response_type" must be one of [id_token, code id_token, code]')
    );
    expect(() => validateAuthorizationParams({ response_type: 'foo id_token' as 'code' })).toThrowError(
      new TypeError('"authorizationParams.response_type" must be one of [id_token, code id_token, code]')
    );
    expect(() => validateAuthorizationParams({ response_type: 'id_token code' as 'code' })).toThrowError(
      new TypeError('"authorizationParams.response_type" must be one of [id_token, code id_token, code]')
    );
  });

  it('should allow valid response_types', () => {
    const config = (authorizationParams: DeepPartial<AuthorizationParameters>): ConfigParameters => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams
    });
    expect(() => validateAuthorizationParams({ response_type: 'id_token' })).not.toThrow();
    expect(() => config({ response_type: 'code id_token' })).not.toThrow();
    expect(() => config({ response_type: 'code' })).not.toThrow();
  });

  it('should not allow empty response_mode', () => {
    expect(() => validateAuthorizationParams({ response_mode: (null as unknown) as undefined })).toThrowError(
      new TypeError('"authorizationParams.response_mode" must be [form_post]')
    );
    expect(() => validateAuthorizationParams({ response_mode: ('' as unknown) as undefined })).toThrowError(
      new TypeError('"authorizationParams.response_mode" must be [form_post]')
    );
    expect(() =>
      validateAuthorizationParams({
        response_type: 'code',
        response_mode: ('' as unknown) as undefined
      })
    ).toThrowError(new TypeError('"authorizationParams.response_mode" must be one of [query, form_post]'));
  });

  it('should not allow response_type id_token and response_mode query', () => {
    expect(() =>
      validateAuthorizationParams({
        response_type: 'id_token',
        response_mode: 'query'
      })
    ).toThrowError(new TypeError('"authorizationParams.response_mode" must be [form_post]'));
    expect(() =>
      validateAuthorizationParams({
        response_type: 'code id_token',
        response_mode: 'query'
      })
    ).toThrowError(new TypeError('"authorizationParams.response_mode" must be [form_post]'));
  });

  it('should allow valid response_type response_mode combinations', () => {
    const config = (authorizationParams: DeepPartial<AuthorizationParameters>): ConfigParameters => ({
      ...defaultConfig,
      clientSecret: 'foo',
      authorizationParams
    });
    expect(() => config({ response_type: 'code', response_mode: 'query' })).not.toThrow();
    expect(() => config({ response_type: 'code', response_mode: 'form_post' })).not.toThrow();
    expect(() =>
      validateAuthorizationParams({
        response_type: 'id_token',
        response_mode: 'form_post'
      })
    ).not.toThrowError();
    expect(() => config({ response_type: 'code id_token', response_mode: 'form_post' })).not.toThrow();
  });
});
