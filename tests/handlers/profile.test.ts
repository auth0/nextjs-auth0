import { withoutApi } from '../helpers/default-settings';
import { userInfo } from '../helpers/oidc-nocks';
import { get } from '../auth0-session/fixture/helpers';
import { setup, teardown, login } from '../helpers/setup';
import { Session } from '../../src/session';

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
    const afterCallback = (_req: any, _res: any, session: Session): Session => {
      delete session.accessToken;
      return session;
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
