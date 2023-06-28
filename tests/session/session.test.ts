import { TokenSet } from 'openid-client';
import { fromJson, fromTokenEndpointResponse } from '../../src/session';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import { Session } from '../../src';

const routes = { login: '', callback: '', postLogoutRedirect: '' };

const getLoginState = () => Promise.resolve({});

describe('session', () => {
  test('should construct a session with a user', async () => {
    expect(new Session({ foo: 'bar' }).user).toEqual({ foo: 'bar' });
  });

  describe('from tokenSet', () => {
    test('should construct a session from a tokenSet', async () => {
      expect(
        fromTokenEndpointResponse(new TokenSet({ id_token: await makeIdToken({ foo: 'bar', bax: 'qux' }) }), {
          identityClaimFilter: ['baz'],
          routes,
          getLoginState,
          session: { storeIDToken: true }
        }).user
      ).toEqual({
        aud: '__test_client_id__',
        bax: 'qux',
        exp: expect.any(Number),
        foo: 'bar',
        iat: expect.any(Number),
        iss: 'https://op.example.com/',
        nickname: '__test_nickname__',
        nonce: '__test_nonce__',
        sub: '__test_sub__'
      });
    });

    test('should store the ID Token by default', async () => {
      expect(
        fromTokenEndpointResponse(new TokenSet({ id_token: await makeIdToken({ foo: 'bar' }) }), {
          identityClaimFilter: ['baz'],
          routes,
          getLoginState,
          session: { storeIDToken: true }
        }).idToken
      ).toBeDefined();
    });

    test('should not store the ID Token', async () => {
      expect(
        fromTokenEndpointResponse(new TokenSet({ id_token: await makeIdToken({ foo: 'bar' }) }), {
          session: {
            storeIDToken: false,
            name: '',
            rolling: false,
            rollingDuration: 0,
            absoluteDuration: 0,
            cookie: { transient: false, httpOnly: false, sameSite: 'lax' }
          },
          getLoginState,
          identityClaimFilter: ['baz'],
          routes
        }).idToken
      ).toBeUndefined();
    });
  });

  describe('from json', () => {
    test('should construct a session from json', () => {
      expect(fromJson({ user: { foo: 'bar' } })?.user).toEqual({ foo: 'bar' });
    });
  });
});
