import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';

describe('get-server-side-props-wrapper', () => {
  afterEach(teardown);

  test('wrap getServerSideProps', async () => {
    const baseUrl = await setup(withoutApi);

    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/wrapped-get-server-side-props', { fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/isAuthenticated: .*false/);
  });

  test('wrap getServerSideProps with session', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/wrapped-get-server-side-props', { fullResponse: true, cookieJar });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/isAuthenticated: .*true/);
  });

  test('wrap getServerSideProps with async props', async () => {
    const baseUrl = await setup(withoutApi, { asyncProps: true });

    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/wrapped-get-server-side-props', { fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/isAuthenticated: .*false/);
  });

  test('wrap getServerSideProps with async props and session', async () => {
    const baseUrl = await setup(withoutApi, { asyncProps: true });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/wrapped-get-server-side-props', { fullResponse: true, cookieJar });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/isAuthenticated: .*true/);
  });
});
