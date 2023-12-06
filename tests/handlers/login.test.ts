/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import { parse as urlParse } from 'url';
import { decodeState } from '../../src/auth0-session/utils/encoding';
import { getResponse, mockFetch } from '../fixtures/app-router-helpers';

describe('login handler (app router)', () => {
  beforeEach(mockFetch);

  test('should create a state', async () => {
    const res = await getResponse({
      url: '/api/auth/login'
    });
    expect(res.cookies.get('auth_verification')).toMatchObject({
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
    expect(decodedState?.returnTo).toEqual('/custom-url');
  });

  test('should redirect to the identity provider', async () => {
    const res = await getResponse({
      url: '/api/auth/login'
    });
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
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
        state,
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
    expect(decodedState).toEqual({
      foo: 'bar',
      returnTo: '/bar'
    });
  });

  test('should allow the returnTo url to be provided in the querystring', async () => {
    const res = await getResponse({
      url: '/api/auth/login?returnTo=/from-query'
    });
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
    expect(decodedState?.returnTo).toEqual('http://www.acme.com/from-query');
  });

  test('should take the first returnTo url provided in the querystring', async () => {
    const res = await getResponse({
      url: '/api/auth/login?returnTo=/foo&returnTo=bar'
    });
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
    expect(decodedState?.returnTo).toEqual('http://www.acme.com/foo');
  });

  test('should not allow absolute urls to be provided in the querystring', async () => {
    const res = await getResponse({
      url: '/api/auth/login?returnTo=https://evil.com'
    });
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
    expect(decodedState?.returnTo).toBeUndefined();
  });

  test('should allow absolute urls in params of returnTo urls', async () => {
    const res = await getResponse({
      url: '/api/auth/login',
      loginOpts: { returnTo: 'https://google.com' }
    });
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
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
    const { value: authVerification } = res.cookies.get('auth_verification');
    const { state } = JSON.parse(authVerification.split('.')[0]);
    const decodedState = decodeState(state);
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

  test('should handle login errors', async () => {
    const res = await getResponse({
      loginOpts: {
        getLoginState() {
          return 1 as any;
        }
      },
      url: '/api/auth/login'
    });
    expect(res.status).toBe(500);
    expect(res.statusText).toMatch(/Login handler failed. CAUSE: Custom state value must be an object/);
  });

  test('should redirect to the identity provider when using pushedAuthorizationRequests', async () => {
    const res = await getResponse({
      url: '/api/auth/login',
      config: {
        clientSecret: '__test_client_secret__',
        clientAuthMethod: 'client_secret_post',
        pushedAuthorizationRequests: true
      }
    });
    expect(urlParse(res.headers.get('location'), true)).toMatchObject({
      protocol: 'https:',
      host: 'acme.auth0.local',
      hash: null,
      query: {
        request_uri: 'foo',
        client_id: '__test_client_id__'
      },
      pathname: '/authorize'
    });
  });

  test('should throw an error if the PAR endpoint returns an error', async () => {
    const res = await getResponse({
      url: '/api/auth/login',
      config: {
        clientSecret: '__test_client_secret__',
        clientAuthMethod: 'client_secret_post',
        pushedAuthorizationRequests: true
      },
      parStatus: 401,
      parPayload: { error: 'invalid_client' }
    });
    expect(res.ok).toBe(false);
    expect(res.statusText).toBe('Login handler failed. CAUSE: invalid_client');
  });
});
