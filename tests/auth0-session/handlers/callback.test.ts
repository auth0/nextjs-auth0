import nock from 'nock';
import { CookieJar } from 'tough-cookie';
import * as jose from 'jose';
import { signing as deriveKey } from '../../../src/auth0-session/utils/hkdf';
import { encodeState } from '../../../src/auth0-session/hooks/get-login-state';
import { SessionResponse, setup, teardown } from '../fixtures/server';
import { makeIdToken } from '../fixtures/cert';
import { toSignedCookieJar, get, post, defaultConfig } from '../fixtures/helpers';

const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });

describe('callback', () => {
  afterEach(teardown);

  it('should error when the body is empty', async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        nonce: '__test_nonce__',
        state: '__test_state__'
      },
      baseURL
    );

    await expect(post(baseURL, '/callback', { body: {}, cookieJar })).rejects.toThrowError(
      'state missing from the response'
    );
  });

  it('should error when the state cookie is missing', async () => {
    const baseURL = await setup(defaultConfig);

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__test_state__',
          id_token: '__invalid_token__'
        },
        cookieJar: new CookieJar()
      })
    ).rejects.toThrowError('checks.state argument is missing');
  });

  it("should error when state doesn't match", async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        nonce: '__valid_nonce__',
        state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__invalid_state__',
          id_token: '__invalid_token__'
        },
        cookieJar
      })
    ).rejects.toThrowError('state mismatch, expected __valid_state__, got: __invalid_state__');
  });

  it("should error when id_token can't be parsed", async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        nonce: '__valid_nonce__',
        state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__valid_state__',
          id_token: '__invalid_token__'
        },
        cookieJar
      })
    ).rejects.toThrowError('failed to decode JWT (JWTMalformed: JWTs must have three components)');
  });

  it('should error when id_token has invalid alg', async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        nonce: '__valid_nonce__',
        state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__valid_state__',
          id_token: await new jose.SignJWT({ sub: '__test_sub__' })
            .setProtectedHeader({ alg: 'HS256' })
            .sign(await deriveKey('secret'))
        },
        cookieJar
      })
    ).rejects.toThrowError('unexpected JWT alg received, expected RS256, got: HS256');
  });

  it('should error when id_token is missing issuer', async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        nonce: '__valid_nonce__',
        state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__valid_state__',
          id_token: await makeIdToken({ iss: undefined })
        },
        cookieJar
      })
    ).rejects.toThrowError('missing required JWT property iss');
  });

  it('should error when nonce is missing from cookies', async () => {
    const baseURL = await setup(defaultConfig);

    const cookieJar = await toSignedCookieJar(
      {
        state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__valid_state__',
          id_token: await makeIdToken({ nonce: '__test_nonce__' })
        },
        cookieJar
      })
    ).rejects.toThrowError('nonce mismatch, expected undefined, got: __test_nonce__');
  });

  it('should error when legacy samesite fallback is off', async () => {
    const baseURL = await setup({ ...defaultConfig, legacySameSiteCookie: false });

    const cookieJar = await toSignedCookieJar(
      {
        _state: '__valid_state__'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: '__valid_state__',
          id_token: await makeIdToken()
        },
        cookieJar
      })
    ).rejects.toThrowError('checks.state argument is missing');
  });

  it('should error for expired ID Token', async () => {
    const baseURL = await setup({ ...defaultConfig, legacySameSiteCookie: false });

    const expected = {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: '__test_client_id__',
      nonce: '__test_nonce__',
      auth_time: 10
    };

    const cookieJar = await toSignedCookieJar(
      {
        state: expectedDefaultState,
        nonce: '__test_nonce__',
        max_age: '100'
      },
      baseURL
    );

    await expect(
      post(baseURL, '/callback', {
        body: {
          state: expectedDefaultState,
          id_token: await makeIdToken(expected)
        },
        cookieJar
      })
    ).rejects.toThrowError('too much time has elapsed since the last End-User authentication');
  });

  it('should expose the id token claims when id_token is valid', async () => {
    const baseURL = await setup({ ...defaultConfig, legacySameSiteCookie: false });

    const expected = {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: '__test_client_id__',
      nonce: '__test_nonce__'
    };

    const cookieJar = await toSignedCookieJar(
      {
        state: expectedDefaultState,
        nonce: '__test_nonce__'
      },
      baseURL
    );

    const { res } = await post(baseURL, '/callback', {
      body: {
        state: expectedDefaultState,
        id_token: await makeIdToken(expected)
      },
      cookieJar,
      fullResponse: true
    });

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });

    expect(res.headers.location).toEqual('https://example.org');
    expect(session.claims).toEqual(expect.objectContaining(expected));
  });

  it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
    const baseURL = await setup({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access'
      }
    });

    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
    });

    nock('https://op.example.com')
      .post('/oauth/token')
      .reply(200, () => ({
        access_token: '__test_access_token__',
        refresh_token: '__test_refresh_token__',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 86400
      }));

    const cookieJar = await toSignedCookieJar(
      {
        state: expectedDefaultState,
        nonce: '__test_nonce__'
      },
      baseURL
    );

    await post(baseURL, '/callback', {
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
      },
      cookieJar
    });

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session).toEqual(
      expect.objectContaining({
        token_type: 'Bearer',
        access_token: '__test_access_token__',
        id_token: idToken,
        refresh_token: '__test_refresh_token__',
        expires_at: expect.any(Number)
      })
    );
  });

  it('should use basic auth on token endpoint when using code flow', async () => {
    const idToken = await makeIdToken({
      c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
    });

    const baseURL = await setup({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token',
        audience: 'https://api.example.com/',
        scope: 'openid profile email read:reports offline_access'
      }
    });

    let credentials = '';
    let body = '';
    nock('https://op.example.com')
      .post('/oauth/token')
      .reply(200, function (_uri, requestBody) {
        credentials = this.req.headers.authorization.replace('Basic ', '');
        body = requestBody as string;
        return {
          access_token: '__test_access_token__',
          refresh_token: '__test_refresh_token__',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 86400
        };
      });

    const cookieJar = await toSignedCookieJar(
      {
        state: expectedDefaultState,
        nonce: '__test_nonce__'
      },
      baseURL
    );

    const code = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
    await post(baseURL, '/callback', {
      body: {
        state: expectedDefaultState,
        id_token: idToken,
        code
      },
      cookieJar
    });

    expect(Buffer.from(credentials, 'base64').toString()).toEqual('__test_client_id__:__test_client_secret__');
    expect(body).toEqual(
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(baseURL)}%2Fcallback`
    );
  });

  it('should redirect to default base url', async () => {
    const baseURL = await setup(defaultConfig);

    const state = encodeState({ foo: 'bar' });
    const cookieJar = await toSignedCookieJar(
      {
        state: state,
        nonce: '__test_nonce__'
      },
      baseURL
    );

    const { res } = await post(baseURL, '/callback', {
      body: {
        state: state,
        id_token: await makeIdToken()
      },
      cookieJar,
      fullResponse: true
    });

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(baseURL);
  });

  it('should accept custom runtime redirect over base url', async () => {
    const redirectUri = 'http://messi:3000/api/auth/callback/runtime';
    const baseURL = await setup(defaultConfig, { callbackOptions: { redirectUri } });
    const state = encodeState({ foo: 'bar' });
    const cookieJar = await toSignedCookieJar({ state, nonce: '__test_nonce__' }, baseURL);
    const { res } = await post(baseURL, '/callback', {
      body: {
        state: state,
        id_token: await makeIdToken()
      },
      cookieJar,
      fullResponse: true
    });

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(baseURL);
  });
});
