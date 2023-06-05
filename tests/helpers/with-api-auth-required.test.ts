import { NextRequest, NextResponse } from 'next/server';
import { login, setup, teardown } from '../fixtures/setup';
import { withApi, withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';
import { getResponse, login as appRouterLogin, getSession } from '../fixtures/app-router-helpers';
import { initAuth0 } from '../../src';

describe('with-api-auth-required', () => {
  describe('app router', () => {
    const getApiResponse = (opts?: any) => {
      const auth0Instance = initAuth0(withApi);
      return getResponse({
        url: '/api/auth/protected',
        auth0Instance,
        extraHandlers: {
          protected(req: NextRequest, ctx: { params: Record<string, any> }) {
            return auth0Instance.withApiAuthRequired(() => {
              return NextResponse.json({ foo: 'bar' });
            })(req, ctx);
          },
          'protected-returns-response'(req: NextRequest, ctx: { params: Record<string, any> }) {
            return auth0Instance.withApiAuthRequired((_req: NextRequest) => {
              // @ts-expect-error This is not in lib/dom right now.
              return Response.json({ foo: 'bar' });
            })(req, ctx);
          }
        },
        ...opts
      });
    };

    test('protect an api route', async () => {
      await expect(getApiResponse()).resolves.toMatchObject({ status: 401 });
    });

    test('allow access to an api route with a valid session', async () => {
      const loginRes = await appRouterLogin();
      const res = await getApiResponse({ cookies: { appSession: loginRes.cookies.get('appSession').value } });
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toEqual({ foo: 'bar' });
      await expect(getSession(withApi, res)).resolves.toMatchObject({
        user: expect.objectContaining({ sub: '__test_sub__' })
      });
    });

    test('allow access to an api route that returns a basic response with a valid session', async () => {
      const loginRes = await appRouterLogin();
      const res = await getApiResponse({
        url: '/api/auth/protected-returns-response',
        cookies: { appSession: loginRes.cookies.get('appSession').value }
      });
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toEqual({ foo: 'bar' });
      await expect(getSession(withApi, res)).resolves.toMatchObject({
        user: expect.objectContaining({ sub: '__test_sub__' })
      });
    });
  });

  describe('page router', () => {
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
});
