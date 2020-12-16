import { parse as urlParse } from 'url';
import { parse } from 'cookie';
import { start, stop } from '../helpers/server';
import { discovery } from '../helpers/oidc-nocks';
import { withoutApi, withApi } from '../helpers/default-settings';
import { LoginOptions, initAuth0 } from '../../src';
import { decodeState } from '../../src/auth0-session/hooks/get-login-state';
import { ConfigParameters } from '../../dist/auth0-session';

const getAsync = ({ url, ...opts }: RequestInit & { url: string }): Promise<Response> => fetch(url, opts);
const parseCookies = (headers: Headers): any => (headers.get('set-cookie') as string).split(',').map((s) => parse(s));
const getCookie = (key: string, cookies: any[]): any => cookies.find((cookie: any) => !!cookie[key]);

const setupHandler = async (
  config: ConfigParameters,
  loginOptions: LoginOptions = { returnTo: '/custom-url' }
): Promise<string> => {
  discovery(config);
  const { handleAuth, handleLogin } = await initAuth0(config);
  (global as any).handleAuth = handleAuth.bind(null, {
    async login(req, res) {
      try {
        await handleLogin(req, res, loginOptions);
      } catch (error) {
        res.status(error.status || 500).end(error.message);
      }
    }
  });
  return start();
};

describe('login handler', () => {
  afterEach(async () => {
    delete (global as any).handleAuth;
    await stop();
    jest.resetModules();
  });

  test('should create a state', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const { headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    expect(cookies).toEqual(
      expect.arrayContaining([
        {
          nonce: expect.any(String),
          Path: '/',
          SameSite: 'Lax'
        },
        {
          state: expect.any(String),
          Path: '/',
          SameSite: 'Lax'
        },
        {
          code_verifier: expect.any(String),
          Path: '/',
          SameSite: 'Lax'
        }
      ])
    );
  });

  test('should add redirectTo to the state', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const { headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);
    expect(state).toBeTruthy();

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState.returnTo).toEqual('/custom-url');
  });

  test('should redirect to the identity provider', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const { status, headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    expect(status).toBe(302);

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);
    expect(urlParse(headers.get('location') as string, true)).toMatchObject({
      protocol: 'https:',
      host: 'acme.auth0.local',
      hash: null,
      query: {
        client_id: '__test_client_id__',
        scope: 'openid profile email',
        response_type: 'code',
        redirect_uri: 'http://www.acme.com/api/auth/callback',
        nonce: expect.any(String),
        state: state.split('.')[0],
        code_challenge: expect.any(String),
        code_challenge_method: 'S256'
      },
      pathname: '/authorize'
    });
  });

  test('should allow sending custom parameters to the authorization server', async () => {
    const loginOptions = {
      authorizationParams: {
        max_age: 123,
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope openid',
        foo: 'bar'
      }
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { status, headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    expect(status).toBe(302);
    expect(urlParse(headers.get('location') as string, true)).toMatchObject({
      query: {
        ...loginOptions.authorizationParams,
        max_age: '123'
      }
    });
  });

  test('should allow adding custom data to the state', async () => {
    const loginOptions = {
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      foo: 'bar',
      returnTo: 'http://www.acme.com/'
    });
  });

  test('should merge returnTo and state', async () => {
    const loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      foo: 'bar',
      returnTo: '/profile'
    });
  });

  test('should allow the getState method to overwrite returnTo', async () => {
    const loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar',
          returnTo: '/foo'
        };
      }
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      foo: 'bar',
      returnTo: '/foo'
    });
  });

  test('should allow the returnTo url to be provided in the querystring', async () => {
    const loginOptions = {
      returnTo: '/profile'
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { headers } = await getAsync({
      url: `${`${baseUrl}/api/auth/login`}?returnTo=/foo`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      returnTo: '/foo'
    });
  });

  test('should not allow absolute urls to be provided in the querystring', async () => {
    const loginOptions = {
      returnTo: '/default-redirect'
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);

    const res = await getAsync({
      url: `${baseUrl}/api/auth/login?returnTo=https://google.com`,
      redirect: 'manual'
    });

    expect(res.status).toBe(500);
    expect(await res.text()).toEqual('Invalid value provided for returnTo, must be a relative url');
  });

  test('should allow the returnTo to be be overwritten by getState() when provided in the querystring', async () => {
    const loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          returnTo: '/foo'
        };
      }
    };
    const baseUrl = await setupHandler(withoutApi, loginOptions);
    const { headers } = await getAsync({
      url: `${`${baseUrl}/api/auth/login`}?returnTo=bar`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      returnTo: '/foo'
    });
  });

  test('should redirect to the identity provider with scope and audience', async () => {
    const baseUrl = await setupHandler(withApi);
    const { status, headers } = await getAsync({
      url: `${baseUrl}/api/auth/login`,
      redirect: 'manual'
    });

    expect(status).toBe(302);

    expect(urlParse(headers.get('location') as string, true).query).toMatchObject({
      scope: 'openid profile read:customer',
      audience: 'https://api.acme.com'
    });
  });
});
