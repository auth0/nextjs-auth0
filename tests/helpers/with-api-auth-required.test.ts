import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';

describe('with-api-auth-required', () => {
  afterEach(teardown);

  test('protect an api route', async () => {
    const baseUrl = await setup(withoutApi);
    await expect(get(baseUrl, '/api/protected')).rejects.toThrow('Unauthorized');
  });

  test('allow access to an api route with a valid session', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/api/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toEqual({ foo: 'bar' });
  });
});
