import { parse as urlParse } from 'url';
import { parse } from 'cookie';
import 'next'; // get fetch polyfil
import HttpServer from '../helpers/server';
import { discovery } from '../helpers/oidc-nocks';
import { withoutApi, withApi } from '../helpers/default-settings';
import { LoginOptions, initAuth0 } from '../../src';
import { decodeState } from '../../src/auth0-session/hooks/get-login-state';

const getAsync = ({ url, ...opts }: RequestInit & { url: string }): Promise<Response> => fetch(url, opts);
const parseCookies = (headers: Headers): any => (headers.get('set-cookie') as string).split(',').map((s) => parse(s));
const getCookie = (key: string, cookies: any[]): any => cookies.find((cookie: any) => !!cookie[key]);

describe('login handler', () => {
  let httpServer: HttpServer;
  let loginOptions: LoginOptions | undefined;

  beforeEach(async () => {
    discovery(withoutApi);
    loginOptions = { returnTo: '/custom-url' };
    const { handleLogin } = await initAuth0(withoutApi);
    httpServer = new HttpServer((req, res) => handleLogin(req, res, loginOptions));
    await httpServer.start();
  });

  afterEach((done) => {
    httpServer.stop(done);
  });

  test('should create a state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
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
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);
    expect(state).toBeTruthy();

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState.returnTo).toEqual('/custom-url');
  });

  test('should redirect to the identity provider', async () => {
    const { status, headers } = await getAsync({
      url: httpServer.getUrl(),
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
        client_id: 'client_id',
        scope: 'openid profile email',
        response_type: 'code',
        redirect_uri: `https://www.acme.com/api/auth/callback`,
        nonce: expect.any(String),
        state: state.split('.')[0],
        code_challenge: expect.any(String),
        code_challenge_method: 'S256'
      },
      pathname: '/authorize'
    });
  });

  test('should allow sending custom parameters to the authorization server', async () => {
    loginOptions = {
      authorizationParams: {
        max_age: 123,
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope openid',
        foo: 'bar'
      }
    };
    const { status, headers } = await getAsync({
      url: httpServer.getUrl(),
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
    loginOptions = {
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      foo: 'bar',
      returnTo: 'https://www.acme.com/'
    });
  });

  test('should merge returnTo and state', async () => {
    loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
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
    loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          foo: 'bar',
          returnTo: '/foo'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
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
    loginOptions = {
      returnTo: '/profile'
    };
    const { headers } = await getAsync({
      url: `${httpServer.getUrl()}?returnTo=/foo`,
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
    loginOptions = {
      returnTo: '/default-redirect'
    };

    const res = await getAsync({
      url: `${httpServer.getUrl()}?returnTo=https://google.com`,
      redirect: 'manual'
    });

    expect(res.status).toBe(500);
    expect(await res.text()).toEqual('Invalid value provided for returnTo, must be a relative url');
  });

  test('should allow the returnTo to be be overwritten by getState() when provided in the querystring', async () => {
    loginOptions = {
      returnTo: '/profile',
      getLoginState: (): Record<string, any> => {
        return {
          returnTo: '/foo'
        };
      }
    };
    const { headers } = await getAsync({
      url: `${httpServer.getUrl()}?returnTo=bar`,
      redirect: 'manual'
    });

    const cookies = parseCookies(headers);
    const { state } = getCookie('state', cookies);

    const decodedState = decodeState(state.split('.')[0]);
    expect(decodedState).toEqual({
      returnTo: '/foo'
    });
  });
});

describe('withApi login handler', () => {
  let httpServer: HttpServer;

  beforeEach(async () => {
    discovery(withApi);
    const { handleLogin } = await initAuth0(withApi);
    httpServer = new HttpServer((req, res) => handleLogin(req, res));
    await httpServer.start();
  });

  afterEach((done) => {
    httpServer.stop(done);
  });

  test('should create a state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
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

  test('should redirect to the identity provider', async () => {
    const { status, headers } = await getAsync({
      url: httpServer.getUrl(),
      redirect: 'manual'
    });

    expect(status).toBe(302);

    expect(urlParse(headers.get('location') as string, true).query).toMatchObject({
      scope: 'openid profile read:customer',
      audience: 'https://api.acme.com'
    });
  });
});
