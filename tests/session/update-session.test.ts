import { NextRequest, NextResponse } from 'next/server';
import { CookieJar } from 'tough-cookie';
import { login, setup, teardown } from '../fixtures/setup';
import { withApi, withoutApi } from '../fixtures/default-settings';
import { get, post } from '../auth0-session/fixtures/helpers';
import { getResponse, login as appRouterLogin, getSession } from '../fixtures/app-router-helpers';
import { initAuth0 } from '../../src';

describe('update-user', () => {
  describe('app router', () => {
    test('should update session', async () => {
      const loginRes = await appRouterLogin();
      const auth0Instance = initAuth0(withApi);
      const res = await getResponse({
        url: '/api/auth/update',
        auth0Instance,
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        extraHandlers: {
          async update(req: NextRequest) {
            const res = new NextResponse();
            const session = await auth0Instance.getSession(req, res);
            await auth0Instance.updateSession(req, res, { ...session, user: { ...session?.user, foo: 'bar' } });
            return res;
          }
        }
      });
      expect(res.status).toBe(200);
      await expect(getSession(withApi, res)).resolves.toMatchObject({ user: expect.objectContaining({ foo: 'bar' }) });
    });

    test('should update session from a server component', async () => {
      const loginRes = await appRouterLogin();
      // Note: An updated session from a React Server Component will not persist
      // because you can't write to a cookie from a RSC in Next.js
      // This test passes because we're mocking the dynamic `cookies` function.
      jest.doMock('next/headers', () => ({ cookies: () => loginRes.cookies }));
      const auth0Instance = initAuth0(withApi);
      const res = await getResponse({
        url: '/api/auth/update',
        auth0Instance,
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        extraHandlers: {
          async update() {
            // const res = new NextResponse();
            const session = await auth0Instance.getSession();
            await auth0Instance.updateSession({ ...session, user: { ...session?.user, foo: 'bar' } });
            return new NextResponse();
          }
        }
      });
      expect(res.status).toBe(200);
      await expect(getSession(withApi, loginRes)).resolves.toMatchObject({
        user: expect.objectContaining({ foo: 'bar' })
      });
    });
  });
  describe('page router', () => {
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
});
