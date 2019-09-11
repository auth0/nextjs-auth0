import request from 'request';
import { promisify } from 'util';
import jose from '@panva/jose';
import callback from '../../src/handlers/callback';
import getClient from '../../src/utils/oidc-client';
import CookieSessionStore from '../../src/session/cookie-store';

import HttpServer from '../helpers/server';
import { withoutApi } from '../helpers/default-settings';
import { discovery, jwksEndpoint, codeExchange } from '../helpers/oidc-nocks';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';

const [getAsync] = [request.get].map(promisify);

describe('callback handler', () => {
  let httpServer: HttpServer;
  let keystore: jose.JWKS.KeyStore;

  beforeAll(() => {
    keystore = new jose.JWKS.KeyStore();
    return keystore.generate('RSA');
  });

  beforeAll((done) => {
    discovery(withoutApi);
    jwksEndpoint(withoutApi, keystore.toJWKS());

    httpServer = new HttpServer(callback(withoutApi, getClient(withoutApi), new CookieSessionStore(
      new CookieSessionStoreSettings({
        cookieSecret: 'keyboardcat-keyboardcat-keyboardcat-keyboardcat'
      })
    )));
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

  test('should sign in the user', async () => {
    codeExchange(withoutApi, 'bar', keystore.get(), {
      name: 'john doe',
      email: 'john@test.com',
      sub: '123'
    });

    const { statusCode, headers } = await getAsync({
      url: `${httpServer.getUrl()}?state=foo&code=bar`,
      followRedirect: false,
      headers: {
        cookie: 'a0:state=foo;'
      }
    });

    expect(statusCode).toBe(302);
    expect(headers['set-cookie'][0]).toContain('a0:session');
    // Todo: test expiration
  });

  test('should validate the audience', async () => {
    const overrides = {
      aud: 'other-audience'
    };

    codeExchange(withoutApi, 'with-invalid-audience', keystore.get(), {
      name: 'john doe',
      email: 'john@test.com',
      sub: '123'
    }, overrides);

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

    codeExchange(withoutApi, 'with-invalid-issuer', keystore.get(), {
      name: 'john doe',
      email: 'john@test.com',
      sub: '123'
    }, overrides);

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
});
