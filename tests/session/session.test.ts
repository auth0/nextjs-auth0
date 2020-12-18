import { TokenSet } from 'openid-client';
import { fromJson, fromTokenSet, Session } from '../../src/session';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import { Config } from '../../src';

describe('session', () => {
  test('should construct a session with a user', async () => {
    expect(new Session({ foo: 'bar' }).user).toEqual({ foo: 'bar' });
  });

  test('should construct a session from a tokenSet', () => {
    expect(
      fromTokenSet(new TokenSet({ id_token: makeIdToken({ foo: 'bar', bax: 'qux' }) }), {
        identityClaimFilter: ['baz']
      } as Config).user
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

  test('should construct a session from json', () => {
    expect(fromJson({ user: { foo: 'bar' } })?.user).toEqual({ foo: 'bar' });
  });
});
