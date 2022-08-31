import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get, post } from '../auth0-session/fixtures/helpers';
import { CookieJar } from 'tough-cookie';

describe('update-user', () => {
  afterEach(teardown);

  test('should update user', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const user = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(user).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    await post(baseUrl, '/api/update-user', { cookieJar, body: { user: { foo: 'bar' } } });
    const updatedUser = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(updatedUser).toMatchObject({ foo: 'bar' });
  });

  test('should ignore updates if user is not defined', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const user = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(user).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    await post(baseUrl, '/api/update-user', { cookieJar, body: { user: undefined } });
    const updatedUser = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(updatedUser).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
  });

  test('should ignore updates if user is not logged in', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = new CookieJar();
    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).resolves.toBe('');
    await post(baseUrl, '/api/update-user', { body: { user: { sub: 'foo' } }, cookieJar });
    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).resolves.toBe('');
  });
});
