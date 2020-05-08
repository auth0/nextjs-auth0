import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';

import HttpServer from '../helpers/server';
import logout from '../../src/handlers/logout';
import { withoutApi } from '../helpers/default-settings';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';
import { discovery } from '../helpers/oidc-nocks';
import { ISessionStore } from '../../src/session/store';
import { ISession } from '../../src/session/session';
import getClient from '../../src/utils/oidc-client';
import nock = require('nock');

const [getAsync] = [request.get].map(promisify);

const now = Date.now();
const sessionStore: ISessionStore = {
  read(): Promise<ISession | null> {
    return Promise.resolve({
      user: {
        sub: '123'
      },
      createdAt: now,
      idToken: 'my-id-token',
      refreshToken: 'my-refresh-token'
    });
  },
  save(): Promise<ISession | null> {
    return Promise.resolve(null);
  }
};

describe('logout handler', () => {
  let httpServer: HttpServer;

  beforeEach(done => {
    httpServer = new HttpServer(logout(withoutApi, new CookieSessionStoreSettings(withoutApi.session), getClient(withoutApi), sessionStore));
    httpServer.start(done);
  });

  afterEach(done => {
    // We mock discovery in different ways, thus it has to be cleaned after each test
    nock.cleanAll();
    httpServer.stop(done);
  });

  test('should redirect to the identity provider', async () => {
    discovery(withoutApi);

    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);
    expect(headers.location).toBe(
      `https://${withoutApi.domain}/v2/logout?client_id=${withoutApi.clientId}&returnTo=https%3A%2F%2Fwww.acme.com`
    );
  });

  test('should use end_session_endpoint if available', async () => {
    discovery(withoutApi, { end_session_endpoint: 'https://my-end-session-endpoint/logout' });

    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);
    expect(headers.location).toBe(
      `https://my-end-session-endpoint/logout?id_token_hint=my-id-token&post_logout_redirect_uri=https%253A%252F%252Fwww.acme.com`
    );
  });

  test('should delete the state and session', async () => {
    discovery(withoutApi);

    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      headers: {
        cookie: ['a0:state=foo', 'a0:session=bar'].join('; ')
      },
      followRedirect: false
    });

    const [stateCookie, sessionCookie] = headers['set-cookie'];
    expect(parse(stateCookie)).toMatchObject({
      'a0:state': '',
      'Max-Age': '-1'
    });
    expect(parse(sessionCookie)).toMatchObject({
      'a0:session': '',
      'Max-Age': '-1'
    });
  });
});

describe('logout handler with cookieDomain', () => {
  const cookieDomain = 'www.acme.com';
  let httpServer: HttpServer;

  beforeAll(done => {
    httpServer = new HttpServer(
      logout(withoutApi, new CookieSessionStoreSettings({
        ...withoutApi.session,
        cookieDomain
      }), getClient(withoutApi), sessionStore)
    );
    httpServer.start(done);
  });

  afterAll(done => {
    httpServer.stop(done);
  });

  test('should delete the state and session', async () => {
    discovery(withoutApi);

    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      headers: {
        cookie: ['a0:state=foo', 'a0:session=bar'].join('; ')
      },
      followRedirect: false
    });

    const [stateCookie, sessionCookie] = headers['set-cookie'];
    expect(parse(stateCookie)).toMatchObject({
      'a0:state': '',
      'Max-Age': '-1'
    });
    expect(parse(sessionCookie)).toMatchObject({
      'a0:session': '',
      'Max-Age': '-1',
      Domain: cookieDomain
    });
  });
});
