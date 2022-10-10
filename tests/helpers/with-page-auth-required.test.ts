import { URL } from 'url';
import { login, setup, teardown } from '../fixtures/setup';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';

describe('with-page-auth-required ssr', () => {
  afterEach(teardown);

  test('protect a page', async () => {
    const baseUrl = await setup(withoutApi);
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    expect(decodeURIComponent(headers.location)).toBe('/api/auth/login?returnTo=/protected');
  });

  test('allow access to a page with a valid session', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode },
      data
    } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/Protected Page.*__test_sub__/);
  });

  test('accept a custom returnTo url', async () => {
    const baseUrl = await setup(withoutApi, { withPageAuthRequiredOptions: { returnTo: '/foo' } });
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    expect(decodeURIComponent(headers.location)).toBe('/api/auth/login?returnTo=/foo');
  });

  test('accept custom server-side props', async () => {
    const spy = jest.fn().mockReturnValue({ props: {} });
    const baseUrl = await setup(withoutApi, {
      withPageAuthRequiredOptions: {
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

  test('allow to override the user prop', async () => {
    const baseUrl = await setup(withoutApi, {
      withPageAuthRequiredOptions: {
        async getServerSideProps() {
          return { props: { user: { sub: 'foo' } } };
        }
      }
    });
    const cookieJar = await login(baseUrl);
    const { data } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(data).toMatch(/Protected Page.*foo/);
  });

  test('allow to override the user prop when using aync props', async () => {
    const baseUrl = await setup(withoutApi, {
      withPageAuthRequiredOptions: {
        async getServerSideProps() {
          return { props: Promise.resolve({ user: { sub: 'foo' } }) };
        }
      }
    });
    const cookieJar = await login(baseUrl);
    const { data } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(data).toMatch(/Protected Page.*foo/);
  });

  test('use a custom login url', async () => {
    process.env.NEXT_PUBLIC_AUTH0_LOGIN = '/api/foo';
    const baseUrl = await setup(withoutApi);
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    expect(decodeURIComponent(headers.location)).toBe('/api/foo?returnTo=/protected');
    delete process.env.NEXT_PUBLIC_AUTH0_LOGIN;
  });

  test('is a no-op when invoked as a client-side protection from the server', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);
    const {
      res: { statusCode }
    } = await get(baseUrl, '/csr-protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
  });

  test('should preserve multiple query params in the returnTo URL', async () => {
    const baseUrl = await setup(withoutApi, { withPageAuthRequiredOptions: { returnTo: '/foo?bar=baz&qux=quux' } });
    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/protected', { fullResponse: true });
    expect(statusCode).toBe(307);
    const url = new URL(headers.location, baseUrl);
    expect(url.searchParams.get('returnTo')).toEqual('/foo?bar=baz&qux=quux');
  });

  test('allow access to a page with a valid session and async props', async () => {
    const baseUrl = await setup(withoutApi, {
      withPageAuthRequiredOptions: {
        getServerSideProps() {
          return Promise.resolve({ props: Promise.resolve({}) });
        }
      }
    });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers },
      data
    } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    expect(data).toMatch(/Protected Page.*__test_sub__/);
    const [cookie] = headers['set-cookie'];
    expect(cookie).toMatch(/^appSession=/);
  });

  test('save session when getServerSideProps completes async', async () => {
    const baseUrl = await setup(withoutApi, {
      withPageAuthRequiredOptions: {
        async getServerSideProps(ctx) {
          await Promise.resolve();
          const session = (global as any).getSession(ctx.req, ctx.res);
          session.test = 'Hello World!';
          return { props: {} };
        }
      }
    });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode }
    } = await get(baseUrl, '/protected', { cookieJar, fullResponse: true });
    expect(statusCode).toBe(200);
    const session = await get(baseUrl, '/api/session', { cookieJar });
    expect(session.test).toBe('Hello World!');
  });
});
