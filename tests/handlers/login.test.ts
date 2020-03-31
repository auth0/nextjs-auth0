import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';

import HttpServer from '../helpers/server';
import { discovery } from '../helpers/oidc-nocks';
import getClient from '../../src/utils/oidc-client';
import { withoutApi, withApi } from '../helpers/default-settings';
import login, { LoginOptions } from '../../src/handlers/login';

const [getAsync] = [request.get].map(promisify);

describe('login handler', () => {
  let httpServer: HttpServer;
  let loginHandler: any;
  let loginOptions: LoginOptions | null;

  beforeEach(done => {
    discovery(withoutApi);
    loginOptions = { redirectTo: '/custom-url' };
    loginHandler = login(withoutApi, getClient(withoutApi));
    httpServer = new HttpServer((req, res) => loginHandler(req, res, loginOptions));
    httpServer.start(done);
  });

  afterEach(done => {
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

  test('should create a redirectTo cookie', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    const redirectTo = parse(headers['set-cookie'][1]);
    expect(state).toBeTruthy();
    expect(redirectTo['a0:redirectTo']).toEqual('/custom-url');
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
});

describe('withApi login handler', () => {
  let httpServer: HttpServer;

  beforeAll(done => {
    discovery(withApi);
    httpServer = new HttpServer(login(withApi, getClient(withApi)));
    httpServer.start(done);
  });

  afterAll(done => {
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
