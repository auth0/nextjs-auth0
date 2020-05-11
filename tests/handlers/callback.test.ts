import jose from '@panva/jose';
import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';
import timekeeper from 'timekeeper';

import callback from '../../src/handlers/callback';
import getClient from '../../src/utils/oidc-client';
import CookieSessionStore from '../../src/session/cookie-store';

import HttpServer from '../helpers/server';
import getRequestResponse from '../helpers/http';
import { withoutApi, withApi } from '../helpers/default-settings';
import { discovery, jwksEndpoint, codeExchange } from '../helpers/oidc-nocks';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';

const [getAsync] = [request.get].map(promisify);

describe('callback handler', () => {
  let keystore: jose.JWKS.KeyStore;
  let store: CookieSessionStore;

  beforeAll(() => {
    keystore = new jose.JWKS.KeyStore();
    store = new CookieSessionStore(
      new CookieSessionStoreSettings({
        cookieSecret: 'keyboardcat-keyboardcat-keyboardcat-keyboardcat',
        cookieLifetime: 60 * 60
      })
    );
    return keystore.generate('RSA');
  });

  describe('without api', () => {
    let httpServer: HttpServer;

    beforeEach((done) => {
      discovery(withoutApi);
      jwksEndpoint(withoutApi, keystore.toJWKS());

      httpServer = new HttpServer(callback(withoutApi, getClient(withoutApi), store));
      httpServer.start(done);
    });

    afterAll((done) => {
      httpServer.stop(done);
    });

    test('should require a state', async () => {
      const { body } = await getAsync({
        url: httpServer.getUrl(),
        followRedirect: false
      });

      expect(body).toBe('Invalid request, an initial state could not be found');
    });

    test('should validate the state', async () => {
      codeExchange(withoutApi, 'bar', keystore.get(), {
        name: 'john doe',
        email: 'john@test.com',
        sub: '123'
      });

      const { statusCode, body } = await getAsync({
        url: `${httpServer.getUrl()}?state=invalid&code=bar`,
        followRedirect: false,
        headers: {
          cookie: 'a0:state=foo;'
        }
      });

      expect(statusCode).toBe(500);
      expect(body).toEqual('state mismatch, expected foo, got: invalid');
    });

    test('should validate the audience', async () => {
      const overrides = {
        aud: 'other-audience'
      };

      codeExchange(
        withoutApi,
        'with-invalid-audience',
        keystore.get(),
        {
          name: 'john doe',
          email: 'john@test.com',
          sub: '123'
        },
        overrides
      );

      const { statusCode, body } = await getAsync({
        url: `${httpServer.getUrl()}?state=foo&code=with-invalid-audience`,
        followRedirect: false,
        headers: {
          cookie: 'a0:state=foo;'
        }
      });

      expect(statusCode).toBe(500);
      expect(body).toEqual('aud mismatch, expected client_id, got: other-audience');
    });

    test('should validate the issuer', async () => {
      const overrides = {
        iss: 'other-issuer'
      };

      codeExchange(
        withoutApi,
        'with-invalid-issuer',
        keystore.get(),
        {
          name: 'john doe',
          email: 'john@test.com',
          sub: '123'
        },
        overrides
      );

      const { statusCode, body } = await getAsync({
        url: `${httpServer.getUrl()}?state=foo&code=with-invalid-issuer`,
        followRedirect: false,
        headers: {
          cookie: 'a0:state=foo;'
        }
      });

      expect(statusCode).toBe(500);
      expect(body).toEqual('unexpected iss value, expected https://acme.auth0.local/, got: other-issuer');
    });

    describe('when oidcClient.clockTolerance is configured', () => {
      test('should allow id_tokens to be set in the future', async () => {
        const overrides = {
          iat: Math.floor(new Date(new Date().getTime() + 10 * 1000).getTime() / 1000)
        };

        const options = {
          ...withoutApi,
          oidcClient: {
            clockTolerance: 12000
          }
        };

        codeExchange(
          withoutApi,
          'with-clock-skew',
          keystore.get(),
          {
            name: 'john doe',
            email: 'john@test.com',
            sub: '123'
          },
          overrides
        );

        httpServer.setHandler(callback(withoutApi, getClient(options), store));
        const { statusCode } = await getAsync({
          url: `${httpServer.getUrl()}?state=foo&code=with-clock-skew`,
          followRedirect: false,
          headers: {
            cookie: 'a0:state=foo;'
          }
        });

        expect(statusCode).toBe(302);
      });
    });

    describe('when signing in the user', () => {
      let time: Date;
      let responseStatus: number;
      let responseHeaders: any;

      beforeAll(async () => {
        time = new Date();
        timekeeper.freeze(time);

        codeExchange(withoutApi, 'bar', keystore.get(), {
          name: 'john doe',
          email: 'john@test.com',
          sub: '123',
          aud: 'my-client',
          iss: 'auth0'
        });

        const { statusCode, headers } = await getAsync({
          url: `${httpServer.getUrl()}?state=foo&code=bar`,
          followRedirect: false,
          headers: {
            cookie: 'a0:state=foo;a0:redirectTo=/custom-url;'
          }
        });

        timekeeper.reset();
        responseStatus = statusCode;
        responseHeaders = headers;
      });

      test('should create the session without OIDC claims', async () => {
        timekeeper.freeze(time);
        expect(responseStatus).toBe(302);
        expect(responseHeaders['set-cookie'][0]).toContain('a0:session');

        const { req } = getRequestResponse();
        req.headers = {
          cookie: `a0:session=${parse(responseHeaders['set-cookie'][0])['a0:session']}`
        };

        const session = await store.read(req);
        expect(session).toStrictEqual({
          createdAt: time.getTime(),
          user: {
            email: 'john@test.com',
            name: 'john doe',
            sub: '123'
          }
        });

        timekeeper.reset();
      });

      test('should set the correct expiration', async () => {
        expect(responseStatus).toBe(302);
        expect(responseHeaders['set-cookie'][0]).toContain('a0:session');

        const cookie = parse(responseHeaders['set-cookie'][0]);
        expect(cookie['Max-Age']).toBe('3600');
        expect(cookie.Expires).toBe(new Date(time.getTime() + 3600 * 1000).toUTCString());
      });

      test('should redirect to cookie url', async () => {
        expect(responseStatus).toBe(302);
        expect(responseHeaders.location).toBe('/custom-url');
      });
    });
  });

  describe('with api', () => {
    let serverWithApi: HttpServer;

    beforeEach((done) => {
      discovery(withApi);
      jwksEndpoint(withApi, keystore.toJWKS());

      store = new CookieSessionStore(
        new CookieSessionStoreSettings({
          storeAccessToken: true,
          storeRefreshToken: true,
          cookieSecret: 'keyboardcat-keyboardcat-keyboardcat-keyboardcat',
          cookieLifetime: 60 * 60
        })
      );
      serverWithApi = new HttpServer(callback(withApi, getClient(withApi), store));
      serverWithApi.start(done);
    });

    afterAll((done) => {
      serverWithApi.stop(done);
    });

    describe('when signing in the user', () => {
      let time: Date;
      let responseStatus: number;
      let responseHeaders: any;

      beforeEach(async () => {
        time = new Date();
        timekeeper.freeze(time);

        codeExchange(withApi, 'something2', keystore.get(), {
          name: 'john doe',
          email: 'john@test.com',
          sub: '123',
          aud: 'client_id',
          iss: 'https://acme.auth0.local/'
        });

        const { statusCode, headers } = await getAsync({
          url: `${serverWithApi.getUrl()}?state=foo&code=something2`,
          followRedirect: false,
          headers: {
            cookie: 'a0:state=foo;'
          }
        });

        timekeeper.reset();
        responseStatus = statusCode;
        responseHeaders = headers;
      });

      test('should create the session without OIDC claims', async () => {
        timekeeper.freeze(time);
        expect(responseStatus).toBe(302);
        expect(responseHeaders['set-cookie'][0]).toContain('a0:session');

        const { req } = getRequestResponse();
        req.headers = {
          cookie: `a0:session=${parse(responseHeaders['set-cookie'][0])['a0:session']}`
        };

        const session = await store.read(req);
        expect(session).toStrictEqual({
          accessToken: 'eyJz93a...k4laUWw',
          refreshToken: 'GEbRxBN...edjnXbL',
          accessTokenExpiresAt: expect.any(Number),
          accessTokenScope: 'read:foo delete:foo',
          createdAt: time.getTime(),
          user: {
            email: 'john@test.com',
            name: 'john doe',
            sub: '123'
          }
        });

        timekeeper.reset();
      });
    });
  });
});
