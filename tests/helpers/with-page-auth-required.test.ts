import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { cookies as nextCookies } from 'next/headers';
import * as navigation from 'next/navigation';
import { NextResponse } from 'next/server';
import { mocked } from 'ts-jest/utils';
import { URL } from 'url';
import { login, setup, teardown } from '../fixtures/setup';
import { login as appRouterLogin } from '../fixtures/app-router-helpers';
import { withApi, withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';
import { initAuth0 } from '../../src';

jest.mock('next/headers');
jest.mock('next/navigation', () => {
  const navigation = jest.requireActual('next/navigation');
  return {
    ...navigation,
    redirect: jest.fn(navigation.redirect)
  };
});

describe('with-page-auth-required ssr', () => {
  describe('app route', () => {
    const getPageResponse = ({ config, cookies, returnTo, loginRes, params, searchParams }: any = {}) => {
      const res = loginRes || new NextResponse();
      mocked(nextCookies).mockImplementation(() => res.cookies as any);
      const opts = { ...withApi, ...config };
      const instance = initAuth0(opts);
      let headers = new Headers();
      if (cookies) {
        headers.set(
          'Cookie',
          Object.entries(cookies)
            .map(([k, v]) => `${k}=${v}`)
            .join('; ')
        );
      }
      const handler = instance.withPageAuthRequired(() => Promise.resolve(React.createElement('div', {}, 'foo')), {
        returnTo
      });
      return handler({ params, searchParams });
    };

    test('protect a page', async () => {
      jest.spyOn(navigation, 'redirect');
      await expect(getPageResponse({})).rejects.toThrowError('NEXT_REDIRECT');
      expect(navigation.redirect).toHaveBeenCalledWith('/api/auth/login');
    });

    test('protect a page and redirect to returnTo option', async () => {
      jest.spyOn(navigation, 'redirect');
      await expect(getPageResponse({ returnTo: '/foo' })).rejects.toThrowError('NEXT_REDIRECT');
      expect(navigation.redirect).toHaveBeenCalledWith('/api/auth/login?returnTo=/foo');
    });

    test('protect a page and redirect to returnTo fn option', async () => {
      jest.spyOn(navigation, 'redirect');
      await expect(
        getPageResponse({
          returnTo({ params, searchParams }: any) {
            const query = new URLSearchParams(searchParams).toString();
            return `/foo/${params.slug}${query ? `?${query}` : ''}`;
          },
          params: { slug: 'bar' },
          searchParams: { foo: 'bar' }
        })
      ).rejects.toThrowError('NEXT_REDIRECT');
      expect(navigation.redirect).toHaveBeenCalledWith('/api/auth/login?returnTo=/foo/bar?foo=bar');
    });

    test('allow access to a page with a valid session', async () => {
      const loginRes = await appRouterLogin();

      const loginCookie = loginRes.cookies.get('appSession');
      const res = await getPageResponse({ loginRes });
      expect(ReactDOMServer.renderToString(res)).toBe('<div>foo</div>');
      expect(loginRes.cookies.get('appSession')).toBeDefined();
      expect(loginRes.cookies.get('appSession')).not.toEqual(loginCookie);
    });

    test('use a custom login url', async () => {
      await expect(
        getPageResponse({ config: { routes: { ...withApi.routes, login: '/api/auth/custom-login' } } })
      ).rejects.toThrowError('NEXT_REDIRECT');
      expect(navigation.redirect).toHaveBeenCalledWith('/api/auth/custom-login');
    });
  });

  describe('page route', () => {
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

    test('allow to override the user prop when using async props', async () => {
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
            const session = await (global as any).getSession(ctx.req, ctx.res);
            await (global as any).updateSession(ctx.req, ctx.res, { ...session, test: 'Hello World!' });
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
});
