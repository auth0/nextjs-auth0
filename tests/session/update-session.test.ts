import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get, post } from '../auth0-session/fixtures/helpers';
import { CookieJar } from 'tough-cookie';

describe('update-user', () => {
  afterEach(teardown);

  test('should update session', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const user = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(user).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    await post(baseUrl, '/api/update-session', { cookieJar, body: { session: { foo: 'bar' } } });
    const updatedSession = await get(baseUrl, '/api/session', { cookieJar });
    expect(updatedSession).toMatchObject({
      foo: 'bar',
      user: expect.objectContaining({ nickname: '__test_nickname__', sub: '__test_sub__' })
    });
  });

  test('should ignore updates if session is not defined', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const user = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(user).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    await post(baseUrl, '/api/update-session', { cookieJar, body: { session: undefined } });
    const updatedUser = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(updatedUser).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
  });

  test('should ignore updates if user is not logged in', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = new CookieJar();
    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).resolves.toBe('');
    await post(baseUrl, '/api/update-session', { body: { session: { sub: 'foo' } }, cookieJar });
    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).resolves.toBe('');
  });

  test('should ignore updates if user is not defined in update', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const user = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(user).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    await post(baseUrl, '/api/update-session', { cookieJar, body: { session: { user: undefined } } });
    const updatedUser = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(updatedUser).toEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
  });
});
