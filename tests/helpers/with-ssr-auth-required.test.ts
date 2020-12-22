import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';

describe('with-ssr-auth-required', () => {
  afterEach(teardown);

  test('protect a page', async () => {
    const baseUrl = await setup(withoutApi);
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    expect(headers.location).toBe('/api/auth/login?returnTo=/protected');
  });

  test('allow access to a page with a valid session', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/<div>Blank Document<\/div>/);
  });

  test('use a custom login url', async () => {
    const baseUrl = await setup(withoutApi, { withSSRAuthRequiredOptions: { loginUrl: '/api/foo' } });
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    expect(headers.location).toBe('/api/foo?returnTo=/protected');
  });

  test('use custom server side props', async () => {
    const spy = jest.fn().mockReturnValue({ props: {} });
    const baseUrl = await setup(withoutApi, {
      withSSRAuthRequiredOptions: {
        getServerSideProps: spy
      }
    });
    const cookieJar = await login(baseUrl);
    const {
      res: { statusCode }
    } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ req: expect.anything(), res: expect.anything() }));
  });
});
