import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';

import HttpServer from '../helpers/server';
import { discovery } from '../helpers/oidc-nocks';
import { decodeState } from '../../src/utils/state';
import getClient from '../../src/utils/oidc-client';
import { withoutApi, withApi } from '../helpers/default-settings';
import login, { LoginOptions } from '../../src/handlers/login';

const [getAsync] = [request.get].map(promisify);

describe('login handler', () => {
  let httpServer: HttpServer;
  let loginHandler: any;
  let loginOptions: LoginOptions | null;

  beforeEach((done) => {
    discovery(withoutApi);
    loginOptions = { redirectTo: '/custom-url' };
    loginHandler = login(withoutApi, getClient(withoutApi));
    httpServer = new HttpServer((req, res) => loginHandler(req, res, loginOptions));
    httpServer.start(done);
  });

  afterEach((done) => {
    httpServer.stop(done);
  });

  test('should create a state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState.nonce).toBeTruthy();
  });

  test('should add redirectTo to the state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState.redirectTo).toEqual('/custom-url');
  });

  test('should redirect to the identity provider', async () => {
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);

    const state = parse(headers['set-cookie'][0]);
    expect(headers.location).toContain(
      `https://${withoutApi.domain}/authorize?` +
        `client_id=${withoutApi.clientId}&scope=${encodeURIComponent(withoutApi.scope)}` +
        `&response_type=code&redirect_uri=${encodeURIComponent(withoutApi.redirectUri)}` +
        `&state=${state['a0:state']}`
    );
  });

  test('should contain the telemetry querystring', async () => {
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });
    expect(statusCode).toBe(302);
    expect(headers.location).toContain('&auth0Client=');
  });

  test('should allow sending custom parameters to the authorization server', async () => {
    loginOptions = {
      authParams: {
        max_age: '123',
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope',
        foo: 'bar'
      }
    };
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);
    expect(headers.location).toContain(
      `https://${withoutApi.domain}/authorize?` +
        `client_id=${withoutApi.clientId}&scope=${encodeURIComponent('some other scope')}` +
        `&response_type=code&redirect_uri=${encodeURIComponent(withoutApi.redirectUri)}`
    );
    expect(headers.location).toContain('&max_age=123&login_hint=foo%40acme.com&ui_locales=nl&foo=bar');
  });

  test('should allow sending custom state to the authorization server', async () => {
    loginOptions = {
      authParams: {
        state: 'custom-state'
      }
    };
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);
    expect(headers.location).toContain('&state=custom-state');
  });

  test('should allow adding custom data to the state', async () => {
    loginOptions = {
      getState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state['a0:state']).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState).toEqual({
      foo: 'bar',
      nonce: expect.any(String)
    });
  });

  test('should merge redirectTo and state', async () => {
    loginOptions = {
      redirectTo: '/profile',
      getState: (): Record<string, any> => {
        return {
          foo: 'bar'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state['a0:state']).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState).toEqual({
      foo: 'bar',
      redirectTo: '/profile',
      nonce: expect.any(String)
    });
  });

  test('should allow the getState method to overwrite redirectTo', async () => {
    loginOptions = {
      redirectTo: '/profile',
      getState: (): Record<string, any> => {
        return {
          foo: 'bar',
          redirectTo: '/other-path'
        };
      }
    };
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state['a0:state']).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState).toEqual({
      foo: 'bar',
      redirectTo: '/other-path',
      nonce: expect.any(String)
    });
  });

  test('should allow the redirectTo url to be provided in the querystring', async () => {
    loginOptions = {
      redirectTo: '/default-redirect'
    };

    const { headers } = await getAsync({
      url: `${httpServer.getUrl()}?redirectTo=/my-profile`,
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state['a0:state']).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState).toEqual({
      redirectTo: '/my-profile',
      nonce: expect.any(String)
    });
  });

  test('should not allow absolute urls to be provided in the querystring', async () => {
    loginOptions = {
      redirectTo: '/default-redirect'
    };

    const { statusCode, body } = await getAsync({
      url: `${httpServer.getUrl()}?redirectTo=https://google.com`,
      followRedirect: false
    });

    expect(statusCode).toBe(500);
    expect(body).toEqual('Invalid value provided for redirectTo, must be a relative url');
  });

  test('should allow the redirectTo url to be be overwritten by getState() when provided in the querystring', async () => {
    loginOptions = {
      redirectTo: '/profile',
      getState: (): Record<string, any> => {
        return {
          foo: 'bar',
          redirectTo: '/other-path'
        };
      }
    };

    const { headers } = await getAsync({
      url: `${httpServer.getUrl()}?redirectTo=/my-profile`,
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state['a0:state']).toBeTruthy();

    const decodedState = decodeState(state['a0:state']);
    expect(decodedState).toEqual({
      foo: 'bar',
      redirectTo: '/other-path',
      nonce: expect.any(String)
    });
  });
});

describe('withApi login handler', () => {
  let httpServer: HttpServer;

  beforeAll((done) => {
    discovery(withApi);
    httpServer = new HttpServer(login(withApi, getClient(withApi)));
    httpServer.start(done);
  });

  afterAll((done) => {
    httpServer.stop(done);
  });

  test('should create a state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state).toBeTruthy();
  });

  test('should redirect to the identity provider', async () => {
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);

    const state = parse(headers['set-cookie'][0]);
    expect(headers.location).toContain(
      `https://${withApi.domain}/authorize?` +
        `client_id=${withApi.clientId}&scope=${encodeURIComponent(withApi.scope)}` +
        `&response_type=code&redirect_uri=${encodeURIComponent(withApi.redirectUri)}` +
        `&audience=${encodeURIComponent(withApi.audience)}` +
        `&state=${state['a0:state']}`
    );
  });
});
