import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';

describe('touch-session', () => {
  afterEach(teardown);

  test('should not update the session when getting the session', async () => {
    const baseUrl = await setup({
      ...withoutApi,
      session: {
        autoSave: false
      }
    });
    const cookieJar = await login(baseUrl);
    const [authCookie] = await cookieJar.getCookies(baseUrl);
    await get(baseUrl, '/api/auth/me', { cookieJar });
    const [updatedAuthCookie] = await cookieJar.getCookies(baseUrl);
    expect(updatedAuthCookie).toEqual(authCookie);
  });

  test('should update the session when calling touchSession', async () => {
    const baseUrl = await setup({
      ...withoutApi,
      session: {
        autoSave: false
      }
    });
    const cookieJar = await login(baseUrl);
    const [authCookie] = await cookieJar.getCookies(baseUrl);
    await get(baseUrl, '/api/touch-session', { cookieJar });
    const [updatedAuthCookie] = await cookieJar.getCookies(baseUrl);
    expect(updatedAuthCookie).not.toEqual(authCookie);
  });

  test('should not throw when there is no session', async () => {
    const baseUrl = await setup({
      ...withoutApi,
      session: {
        autoSave: false
      }
    });
    await expect(get(baseUrl, '/api/touch-session')).resolves.not.toThrow();
  });
});
