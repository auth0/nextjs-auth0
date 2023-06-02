import { parse as urlParse } from 'url';
import { withoutApi, withApi } from '../fixtures/default-settings';
import { decodeState } from '../../src/auth0-session/utils/encoding';
import { setup, teardown } from '../fixtures/setup';
import { get, getCookie } from '../auth0-session/fixtures/helpers';
import { Cookie, CookieJar } from 'tough-cookie';
import { getResponse } from '../fixtures/app-router-helpers';

describe('login handler', () => {
  describe('app router', () => {
    test('should create a state', async () => {
      const res = await getResponse({
        url: '/api/auth/login'
      });
      expect(res.cookies.get('nonce')).toMatchObject({
        value: expect.any(String),
        path: '/',
        sameSite: 'lax'
      });
      expect(res.cookies.get('state')).toMatchObject({
        value: expect.any(String),
        path: '/',
        sameSite: 'lax'
      });
      expect(res.cookies.get('code_verifier')).toMatchObject({
        value: expect.any(String),
        path: '/',
        sameSite: 'lax'
      });
    });

    test('should add returnTo to the state', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts: { returnTo: '/custom-url' }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toEqual('/custom-url');
    });

    test('should redirect to the identity provider', async () => {
      const res = await getResponse({
        url: '/api/auth/login'
      });
      const { value: state } = res.cookies.get('state');
      expect(urlParse(res.headers.get('location'), true)).toMatchObject({
        protocol: 'https:',
        host: 'acme.auth0.local',
        hash: null,
        query: {
          client_id: '__test_client_id__',
          scope: 'openid profile read:customer',
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
      const loginOpts = {
        authorizationParams: {
          max_age: 123,
          login_hint: 'foo@acme.com',
          ui_locales: 'nl',
          scope: 'some other scope openid',
          foo: 'bar',
          organization: 'foo',
          invitation: 'bar'
        }
      };
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts
      });
      expect(res.status).toBe(302);
      expect(urlParse(res.headers.get('location'), true)).toMatchObject({
        query: {
          ...loginOpts.authorizationParams,
          max_age: '123'
        }
      });
    });

    test('should pass organization config to the authorization server', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        config: { organization: 'foo' }
      });
      expect(res.status).toBe(302);
      expect(urlParse(res.headers.get('location'), true).query).toMatchObject({
        organization: 'foo'
      });
    });

    test('should prefer organization auth param to config', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        config: { organization: 'foo' },
        loginOpts: { authorizationParams: { organization: 'bar' } }
      });
      expect(res.status).toBe(302);
      expect(urlParse(res.headers.get('location'), true).query).toMatchObject({
        organization: 'bar'
      });
    });

    test('should allow adding custom data to the state', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts: {
          getLoginState() {
            return { foo: 'bar' };
          }
        }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        foo: 'bar',
        returnTo: 'http://www.acme.com/'
      });
    });

    test('should merge returnTo and state', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts: {
          returnTo: '/profile',
          getLoginState() {
            return { foo: 'bar' };
          }
        }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        foo: 'bar',
        returnTo: '/profile'
      });
    });

    test('should allow the getState method to overwrite returnTo', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts: {
          returnTo: '/profile',
          getLoginState() {
            return { foo: 'bar', returnTo: '/bar' };
          }
        }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        foo: 'bar',
        returnTo: '/bar'
      });
    });

    test('should allow the returnTo url to be provided in the querystring', async () => {
      const res = await getResponse({
        url: '/api/auth/login?returnTo=/from-query'
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toEqual('http://www.acme.com/from-query');
    });

    test('should take the first returnTo url provided in the querystring', async () => {
      const res = await getResponse({
        url: '/api/auth/login?returnTo=/foo&returnTo=bar'
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toEqual('http://www.acme.com/foo');
    });

    test('should not allow absolute urls to be provided in the querystring', async () => {
      const res = await getResponse({
        url: '/api/auth/login?returnTo=https://evil.com'
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toBeUndefined();
    });

    test('should allow absolute urls in params of returnTo urls', async () => {
      const res = await getResponse({
        url: '/api/auth/login',
        loginOpts: { returnTo: 'https://google.com' }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toBe('https://google.com');
    });

    test('should redirect relative to the redirect_uri over the base url', async () => {
      const loginOpts = {
        authorizationParams: {
          redirect_uri: 'https://other-org.acme.com/api/auth/callback'
        }
      };
      const res = await getResponse({
        url: '/api/auth/login?returnTo=/bar',
        loginOpts
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toBe('https://other-org.acme.com/bar');
    });

    test('should allow the returnTo to be be overwritten by getState() when provided in the querystring', async () => {
      const res = await getResponse({
        url: '/api/auth/login?returnTo=/foo',
        loginOpts: {
          getLoginState() {
            return { returnTo: '/bar' };
          }
        }
      });
      const { value: state } = res.cookies.get('state');
      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toBe('/bar');
    });

    test('should redirect to the identity provider with scope and audience', async () => {
      const res = await getResponse({
        config: { authorizationParams: { scope: 'openid profile foobar', audience: 'https://api.acme.com/foo' } },
        url: '/api/auth/login'
      });
      expect(res.status).toBe(302);
      expect(urlParse(res.headers.get('location'), true).query).toMatchObject({
        scope: 'openid profile foobar',
        audience: 'https://api.acme.com/foo'
      });
    });
  });

  describe('page router', () => {
    afterEach(teardown);

    test('should create a state', async () => {
      const baseUrl = await setup(withoutApi);
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });

      expect(cookieJar.getCookiesSync(baseUrl)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            key: 'nonce',
            value: expect.any(String),
            path: '/',
            sameSite: 'lax'
          }),
          expect.objectContaining({
            key: 'state',
            value: expect.any(String),
            path: '/',
            sameSite: 'lax'
          }),
          expect.objectContaining({
            key: 'code_verifier',
            value: expect.any(String),
            path: '/',
            sameSite: 'lax'
          })
        ])
      );
    });

    test('should add returnTo to the state', async () => {
      const baseUrl = await setup(withoutApi, { loginOptions: { returnTo: '/custom-url' } });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });

      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;
      expect(state).toBeTruthy();

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState?.returnTo).toEqual('/custom-url');
    });

    test('should redirect to the identity provider', async () => {
      const baseUrl = await setup(withoutApi);
      const cookieJar = new CookieJar();
      const {
        res: { statusCode, headers }
      } = await get(baseUrl, '/api/auth/login', { cookieJar, fullResponse: true });

      expect(statusCode).toBe(302);

      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;
      expect(urlParse(headers.location, true)).toMatchObject({
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
          foo: 'bar',
          organization: 'foo',
          invitation: 'bar'
        }
      };
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      const {
        res: { statusCode, headers }
      } = await get(baseUrl, '/api/auth/login', { cookieJar, fullResponse: true });

      expect(statusCode).toBe(302);
      expect(urlParse(headers.location, true)).toMatchObject({
        query: {
          ...loginOptions.authorizationParams,
          max_age: '123'
        }
      });
    });

    test('should pass organization config to the authorization server', async () => {
      const baseUrl = await setup({ ...withoutApi, organization: 'foo' });
      const cookieJar = new CookieJar();
      const {
        res: { statusCode, headers }
      } = await get(baseUrl, '/api/auth/login', { cookieJar, fullResponse: true });

      expect(statusCode).toBe(302);
      expect(urlParse(headers.location, true)).toMatchObject({
        query: {
          organization: 'foo'
        }
      });
    });

    test('should prefer organization auth param to config', async () => {
      const baseUrl = await setup(
        { ...withoutApi, organization: 'foo' },
        { loginOptions: { authorizationParams: { organization: 'bar' } } }
      );
      const cookieJar = new CookieJar();
      const {
        res: { statusCode, headers }
      } = await get(baseUrl, '/api/auth/login', { cookieJar, fullResponse: true });

      expect(statusCode).toBe(302);
      expect(urlParse(headers.location, true)).toMatchObject({
        query: {
          organization: 'bar'
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
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });

      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

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
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });

      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

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
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });

      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

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
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login?returnTo=/foo', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        returnTo: new URL('/foo', withoutApi.baseURL).toString()
      });
    });

    test('should take the first returnTo url provided in the querystring', async () => {
      const loginOptions = {
        returnTo: '/profile'
      };
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login?returnTo=/foo&returnTo=/bar', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        returnTo: new URL('/foo', withoutApi.baseURL).toString()
      });
    });

    test('should not allow absolute urls to be provided in the querystring', async () => {
      const loginOptions = {
        returnTo: '/default-redirect'
      };
      const baseUrl = await setup(withoutApi, { loginOptions });

      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login?returnTo=https://www.google.com', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({});
    });

    test('should allow absolute urls in params of returnTo urls', async () => {
      const loginOptions = {
        returnTo: '/default-redirect'
      };
      const baseUrl = await setup(withoutApi, { loginOptions });

      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login?returnTo=/foo?url=https://www.google.com', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        returnTo: new URL('/foo?url=https://www.google.com', withoutApi.baseURL).toString()
      });
    });

    test('should redirect relative to the redirect_uri over the base url', async () => {
      const loginOptions = {
        returnTo: '/default-redirect',
        authorizationParams: {
          redirect_uri: 'https://other-org.acme.com/api/auth/callback'
        }
      };
      const baseUrl = await setup(withoutApi, { loginOptions });

      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login?returnTo=/foo', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        returnTo: 'https://other-org.acme.com/foo'
      });
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
      const baseUrl = await setup(withoutApi, { loginOptions });
      const cookieJar = new CookieJar();
      await get(baseUrl, '/api/auth/login', { cookieJar });
      const { value: state } = getCookie('state', cookieJar, baseUrl) as Cookie;

      const decodedState = decodeState(state.split('.')[0]);
      expect(decodedState).toEqual({
        returnTo: '/foo'
      });
    });

    test('should redirect to the identity provider with scope and audience', async () => {
      const baseUrl = await setup(withApi);
      const {
        res: { statusCode, headers }
      } = await get(baseUrl, '/api/auth/login', { fullResponse: true });

      expect(statusCode).toBe(302);

      expect(urlParse(headers.location, true).query).toMatchObject({
        scope: 'openid profile read:customer',
        audience: 'https://api.acme.com'
      });
    });
  });
});
