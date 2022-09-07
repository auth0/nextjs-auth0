import { TokenSet } from 'openid-client';
import { fromJson, fromTokenSet } from '../../src/session';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import { Session } from '../../src';

describe('session', () => {
  test('should construct a session with a user', async () => {
    expect(new Session({ foo: 'bar' }).user).toEqual({ foo: 'bar' });
  });

  describe('from tokenSet', () => {
    test('should construct a session from a tokenSet', () => {
      expect(
        fromTokenSet(new TokenSet({ id_token: makeIdToken({ foo: 'bar', bax: 'qux' }) }), {
          identityClaimFilter: ['baz'],
          routes: { login: '', callback: '', postLogoutRedirect: '' }
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

    test('should not store the ID Token by default', () => {
      expect(
        fromTokenSet(new TokenSet({ id_token: makeIdToken({ foo: 'bar' }) }), {
          identityClaimFilter: ['baz'],
          routes: { login: '', callback: '', postLogoutRedirect: '' }
        }).idToken
      ).toBeUndefined();
    });

    test('should store the ID Token', () => {
      expect(
        fromTokenSet(new TokenSet({ id_token: makeIdToken({ foo: 'bar' }) }), {
          session: {
            storeIDToken: true,
            name: '',
            rolling: false,
            rollingDuration: 0,
            absoluteDuration: 0,
            cookie: { transient: false, httpOnly: false, sameSite: 'lax' }
          },
          identityClaimFilter: ['baz'],
          routes: { login: '', callback: '', postLogoutRedirect: '' }
        }).idToken
      ).not.toBeUndefined();
    });
  });

  describe('from json', () => {
    test('should construct a session from json', () => {
      expect(fromJson({ user: { foo: 'bar' } })?.user).toEqual({ foo: 'bar' });
    });
  });
});
