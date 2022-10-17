import { parse } from 'url';
import { CookieJar } from 'tough-cookie';
import { setup, teardown } from '../fixtures/server';
import { defaultConfig, fromCookieJar, get, getCookie } from '../fixtures/helpers';
import { decodeState, encodeState } from '../../../src/auth0-session/utils/encoding';
import { LoginOptions } from '../../../src/auth0-session';
import { IncomingMessage } from 'http';

describe('login', () => {
  afterEach(teardown);

  it('should redirect to the authorize url for /login', async () => {
    const baseURL = await setup(defaultConfig);
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const parsed = parse(res.headers.location, true);
    expect(parsed).toMatchObject({
      host: 'op.example.com',
      hostname: 'op.example.com',
      pathname: '/authorize',
      protocol: 'https:',
      query: expect.objectContaining({
        client_id: '__test_client_id__',
        nonce: expect.any(String),
        redirect_uri: `${baseURL}/callback`,
        response_mode: 'form_post',
        response_type: 'id_token',
        scope: 'openid profile email',
        state: encodeState({ returnTo: baseURL })
      })
    });

    expect(fromCookieJar(cookieJar, baseURL)).toMatchObject({
      _state: parsed.query.state,
      _nonce: parsed.query.nonce
    });
  });

  it('should redirect to the authorize url for /login in code flow', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code'
      }
    });
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const parsed = parse(res.headers.location, true);
    expect(parsed).toMatchObject({
      host: 'op.example.com',
      hostname: 'op.example.com',
      pathname: '/authorize',
      protocol: 'https:',
      query: expect.objectContaining({
        client_id: '__test_client_id__',
        nonce: expect.any(String),
        code_challenge: expect.any(String),
        code_challenge_method: 'S256',
        redirect_uri: `${baseURL}/callback`,
        response_type: 'code',
        scope: 'openid profile email',
        state: encodeState({ returnTo: baseURL })
      })
    });

    expect(fromCookieJar(cookieJar, baseURL)).toMatchObject({
      code_verifier: expect.any(String),
      state: parsed.query.state,
      nonce: parsed.query.nonce
    });
  });

  it('should redirect to the authorize url for /login in hybrid flow', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code id_token'
      }
    });
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const parsed = parse(res.headers.location, true);
    expect(parsed).toMatchObject({
      host: 'op.example.com',
      hostname: 'op.example.com',
      pathname: '/authorize',
      protocol: 'https:',
      query: expect.objectContaining({
        client_id: '__test_client_id__',
        nonce: expect.any(String),
        code_challenge: expect.any(String),
        code_challenge_method: 'S256',
        redirect_uri: `${baseURL}/callback`,
        response_type: 'code id_token',
        scope: 'openid profile email',
        state: encodeState({ returnTo: baseURL })
      })
    });

    expect(fromCookieJar(cookieJar, baseURL)).toMatchObject({
      _code_verifier: expect.any(String),
      _state: parsed.query.state,
      _nonce: parsed.query.nonce
    });
  });

  it('should check custom max_age', async () => {
    const baseURL = await setup(defaultConfig, { loginOptions: { authorizationParams: { max_age: 100 } } });
    const cookieJar = new CookieJar();

    await get(baseURL, '/login', { fullResponse: true, cookieJar });

    expect(fromCookieJar(cookieJar, baseURL)).toEqual(
      expect.objectContaining({
        _max_age: '100'
      })
    );
  });

  it('should allow custom login returnTo param', async () => {
    const baseURL = await setup(defaultConfig, { loginOptions: { returnTo: '/foo' } });
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const parsed = parse(res.headers.location, true);
    const decodedState = decodeState(parsed.query.state as string);

    expect(decodedState).toMatchObject({
      returnTo: '/foo'
    });

    expect(fromCookieJar(cookieJar, baseURL)._state).toEqual(parsed.query.state);
  });

  it('should not allow removing openid from scope', async () => {
    const baseURL = await setup(defaultConfig, { loginOptions: { authorizationParams: { scope: 'email' } } });

    await expect(get(baseURL, '/login')).rejects.toThrow('scope should contain "openid"');
  });

  it('should not allow an invalid response_type', async function () {
    const baseURL = await setup(defaultConfig, {
      loginOptions: { authorizationParams: { response_type: 'invalid' as 'id_token' } }
    });

    await expect(get(baseURL, '/login')).rejects.toThrow(
      'response_type should be one of id_token, code id_token, code'
    );
  });

  it('should store response_type if different from config', async function () {
    const cookieJar = new CookieJar();
    const baseURL = await setup(
      {
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: { response_type: 'code id_token' }
      },
      {
        loginOptions: { authorizationParams: { response_type: 'code' } }
      }
    );

    await get(baseURL, '/login', { cookieJar });
    expect(fromCookieJar(cookieJar, baseURL)._response_type).toEqual('code');
  });

  it('should use a custom state builder', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      getLoginState: (_req: IncomingMessage, opts: LoginOptions) => {
        return {
          returnTo: opts.returnTo + '/custom-page',
          customProp: '__test_custom_prop__'
        };
      }
    });
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const parsed = parse(res.headers.location, true);
    const decodedState = decodeState(parsed.query.state as string);

    expect(decodedState).toMatchObject({
      returnTo: `${baseURL}/custom-page`,
      customProp: '__test_custom_prop__'
    });

    expect(fromCookieJar(cookieJar, baseURL)._state).toEqual(parsed.query.state);
  });

  it('should throw on invalid state from custom state builder', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      getLoginState: () => 'invalid'
    });
    await expect(get(baseURL, '/login')).rejects.toThrow('Custom state value must be an object.');
  });

  it('transient cookie SameSite should default to lax in code flow', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      clientSecret: '__test_client_secret__',
      authorizationParams: {
        response_type: 'code'
      }
    });
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const cookie = getCookie('state', cookieJar, baseURL);
    expect(cookie?.sameSite).toEqual('lax');
    expect(cookie?.secure).toBeFalsy();
  });

  it('transient cookie SameSite should honor cookie config in code flow', async () => {
    const baseURL = await setup(
      {
        ...defaultConfig,
        clientSecret: '__test_client_secret__',
        authorizationParams: {
          response_type: 'code'
        },
        session: {
          cookie: {
            sameSite: 'none'
          }
        }
      },
      { https: true }
    );
    const cookieJar = new CookieJar();

    const { res } = await get(baseURL, '/login', { fullResponse: true, cookieJar });
    expect(res.statusCode).toEqual(302);

    const cookie = getCookie('state', cookieJar, baseURL);
    expect(cookie?.sameSite).toEqual('none');
    expect(cookie?.secure).toBeTruthy();
  });
});
