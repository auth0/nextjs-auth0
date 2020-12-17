import { withoutApi } from '../helpers/default-settings';
import { userInfo } from '../helpers/oidc-nocks';
import { get, post, toSignedCookieJar } from '../auth0-session/fixture/helpers';
import { CookieJar } from 'tough-cookie';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { TokenSet } from 'openid-client';
import { setup, teardown } from '../helpers/setup';

const login = async (baseUrl: string): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: '/' });
  const cookieJar = toSignedCookieJar({ state, nonce }, baseUrl);
  await post(baseUrl, '/api/auth/callback', {
    fullResponse: true,
    body: {
      state,
      code: 'code'
    },
    cookieJar
  });
  return cookieJar;
};

describe('profile handler', () => {
  afterEach(teardown);

  test('should throw an error when not logged in', async () => {
    const baseUrl = await setup(withoutApi);

    await expect(get(baseUrl, '/api/auth/me')).rejects.toThrow('Unauthorized');
  });

  test('should return the profile when logged in', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toStrictEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
  });

  test('should throw if re-fetching with no Access Token', async () => {
    const afterCallback = (_req: any, _res: any, tokenSet: TokenSet): TokenSet => {
      delete tokenSet.access_token;
      return tokenSet;
    };
    const baseUrl = await setup(withoutApi, { profileOptions: { refetch: true }, callbackOptions: { afterCallback } });
    const cookieJar = await login(baseUrl);

    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrow(
      'The user does not have a valid access token.'
    );
  });

  test('should refetch the user and update the session', async () => {
    const baseUrl = await setup(withoutApi, { profileOptions: { refetch: true }, userInfoPayload: { foo: 'bar' } });
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
    // check that the session is saved
    userInfo(withoutApi, 'eyJz93a...k4laUWw', {});
    const profile2 = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile2).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
  });
});
