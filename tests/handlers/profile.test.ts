import nock from 'nock';
import { withApi, withoutApi } from '../fixtures/default-settings';
import { refreshTokenRotationExchange, userInfo } from '../fixtures/oidc-nocks';
import { get } from '../auth0-session/fixtures/helpers';
import { setup, teardown, login } from '../fixtures/setup';
import { Session, AfterCallbackPageRoute } from '../../src';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import {
  getResponse,
  login as appRouterLogin,
  getSession as appRouterGetSession
} from '../fixtures/app-router-helpers';
import { NextRequest } from 'next/server';

jest.mock('next/headers');

describe('profile handler', () => {
  describe('app router', () => {
    test('should be empty when not logged in', async () => {
      await expect(getResponse({ url: '/api/auth/me' })).resolves.toMatchObject({ status: 204 });
    });

    test('should return the profile when logged in', async () => {
      const loginRes = await appRouterLogin();
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value }
      });
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toMatchObject({ nickname: '__test_nickname__', sub: '__test_sub__' });
    });

    test('should not allow caching the profile response', async () => {
      const loginRes = await appRouterLogin();
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value }
      });
      expect(res.headers.get('cache-control')).toBe('no-store');
    });

    test('should not allow caching the profile response when refetch is true', async () => {
      const loginRes = await appRouterLogin();
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        profileOpts: { refetch: true }
      });
      expect(res.headers.get('cache-control')).toBe('no-store');
    });

    test('should throw if re-fetching with no access token', async () => {
      const loginRes = await appRouterLogin({
        callbackOpts: {
          afterCallback(_req: any, session: any): Session {
            delete session.accessToken;
            return session;
          }
        }
      });
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        profileOpts: { refetch: true }
      });
      expect(res.status).toBe(500);
      expect(res.statusText).toMatch(/The user does not have a valid access token/);
    });

    test('should refetch the user and update the session', async () => {
      const loginRes = await appRouterLogin();
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        profileOpts: { refetch: true },
        userInfoPayload: { foo: 'bar' }
      });
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toMatchObject({ foo: 'bar' });
    });

    test("should refetch the user and fail if it can't get an access token", async () => {
      const loginRes = await appRouterLogin({
        callbackOpts: {
          afterCallback(_req: NextRequest, session: Session) {
            session.accessTokenExpiresAt = -60;
            return session;
          }
        }
      });
      //mocked(cookies).mockImplementation(() => loginRes.cookies);
      nock.cleanAll();
      nock(`${withApi.issuerBaseURL}`)
        .post('/oauth/token', `grant_type=refresh_token&refresh_token=GEbRxBN...edjnXbL`)
        .reply(200, {
          id_token: await makeIdToken({ iss: 'https://acme.auth0.local/' }),
          token_type: 'Bearer',
          expires_in: 750,
          scope: 'read:foo write:foo'
        });

      await expect(
        getResponse({
          url: '/api/auth/me',
          cookies: { appSession: loginRes.cookies.get('appSession').value },
          profileOpts: { refetch: true },
          userInfoPayload: { foo: 'bar' },
          clearNock: false,
          userInfoToken: 'new-access-token'
        })
      ).resolves.toMatchObject({
        status: 500,
        statusText: expect.stringMatching(/No access token available to refetch the profile/)
      });
    });

    test('should refetch the user and preserve new tokens', async () => {
      const loginRes = await appRouterLogin({
        callbackOpts: {
          afterCallback(_req: NextRequest, session: Session) {
            session.accessTokenExpiresAt = -60;
            return session;
          }
        }
      });
      //mocked(cookies).mockImplementation(() => loginRes.cookies);
      nock.cleanAll();
      await refreshTokenRotationExchange(withApi, 'GEbRxBN...edjnXbL', {}, 'new-access-token', 'new-refresh-token');
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        profileOpts: { refetch: true },
        userInfoPayload: { foo: 'bar' },
        clearNock: false,
        userInfoToken: 'new-access-token'
      });
      expect(res.status).toBe(200);
      await expect(appRouterGetSession(withApi, res)).resolves.toMatchObject({
        user: expect.objectContaining({ foo: 'bar' }),
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token'
      });
      await expect(res.json()).resolves.toMatchObject({ foo: 'bar' });
    });

    test('should update the session in the afterRefetch hook', async () => {
      const loginRes = await appRouterLogin();
      const res = await getResponse({
        url: '/api/auth/me',
        cookies: { appSession: loginRes.cookies.get('appSession').value },
        profileOpts: {
          refetch: true,
          afterRefetch(_req: NextRequest, session: Session) {
            return { ...session, user: { ...session.user, foo: 'baz' } };
          }
        }
      });
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toMatchObject({ foo: 'baz' });
    });

    test('should throw from the afterRefetch hook', async () => {
      const loginRes = await appRouterLogin();
      await expect(
        getResponse({
          url: '/api/auth/me',
          cookies: { appSession: loginRes.cookies.get('appSession').value },
          profileOpts: {
            refetch: true,
            afterRefetch() {
              throw new Error('some validation error');
            }
          }
        })
      ).resolves.toMatchObject({ status: 500, statusText: expect.stringMatching(/some validation error/) });
    });
  });
  describe('page router', () => {
    afterEach(teardown);

    test('should throw an error when not logged in', async () => {
      const baseUrl = await setup(withoutApi);

      await expect(get(baseUrl, '/api/auth/me')).resolves.toBe('');
    });

    test('should return the profile when logged in', async () => {
      const baseUrl = await setup(withoutApi);
      const cookieJar = await login(baseUrl);

      const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
      expect(profile).toStrictEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    });

    test('should not allow caching the profile response', async () => {
      const baseUrl = await setup(withoutApi);
      const cookieJar = await login(baseUrl);

      const { res } = await get(baseUrl, '/api/auth/me', { cookieJar, fullResponse: true });
      expect(res.headers['cache-control']).toEqual('no-store');
    });

    test('should not allow caching the profile response when refetch is true', async () => {
      const baseUrl = await setup(withoutApi, { profileOptions: { refetch: true } });
      const cookieJar = await login(baseUrl);

      const { res } = await get(baseUrl, '/api/auth/me', { cookieJar, fullResponse: true });
      expect(res.headers['cache-control']).toEqual('no-store');
    });

    test('should throw if re-fetching with no access token', async () => {
      const afterCallback: AfterCallbackPageRoute = (_req, _res, session: Session): Session => {
        delete session.accessToken;
        return session;
      };
      const baseUrl = await setup(withoutApi, {
        profileOptions: { refetch: true },
        callbackOptions: { afterCallback }
      });
      const cookieJar = await login(baseUrl);

      await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrow(
        'The user does not have a valid access token.'
      );
    });

    test('should refetch the user and update the session', async () => {
      const baseUrl = await setup(withoutApi, { profileOptions: { refetch: true }, userInfoPayload: { foo: 'bar' } });
      const cookieJar = await login(baseUrl);

      const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
      expect(profile).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
      // check that the session is saved
      userInfo(withoutApi, 'eyJz93a...k4laUWw', {});
      const profile2 = await get(baseUrl, '/api/auth/me', { cookieJar });
      expect(profile2).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
    });

    test("should refetch the user and fail if it can't get an access token", async () => {
      const afterCallback: AfterCallbackPageRoute = (_req, _res, session: Session): Session => {
        session.accessTokenExpiresAt = -60;
        return session;
      };
      const baseUrl = await setup(withoutApi, {
        profileOptions: { refetch: true },
        userInfoPayload: { foo: 'bar' },
        callbackOptions: {
          afterCallback
        }
      });
      const cookieJar = await login(baseUrl);

      nock(`${withoutApi.issuerBaseURL}`)
        .post('/oauth/token', `grant_type=refresh_token&refresh_token=GEbRxBN...edjnXbL`)
        .reply(200, {
          id_token: await makeIdToken({ iss: 'https://acme.auth0.local/' }),
          token_type: 'Bearer',
          expires_in: 750,
          scope: 'read:foo write:foo'
        });
      await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrow(
        'No access token available to refetch the profile'
      );
    });

    test('should refetch the user and preserve new tokens', async () => {
      const afterCallback: AfterCallbackPageRoute = (_req, _res, session: Session): Session => {
        session.accessTokenExpiresAt = -60;
        return session;
      };
      const baseUrl = await setup(withApi, {
        profileOptions: { refetch: true },
        userInfoPayload: { foo: 'bar' },
        callbackOptions: {
          afterCallback
        },
        userInfoToken: 'new-access-token'
      });
      await refreshTokenRotationExchange(withApi, 'GEbRxBN...edjnXbL', {}, 'new-access-token', 'new-refresh-token');
      const cookieJar = await login(baseUrl);
      const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
      expect(profile).toMatchObject({ foo: 'bar' });
      const session = await get(baseUrl, '/api/session', { cookieJar });
      expect(session.accessToken).toEqual('new-access-token');
      expect(session.refreshToken).toEqual('new-refresh-token');
    });

    test('should update the session in the afterRefetch hook', async () => {
      const baseUrl = await setup(withoutApi, {
        profileOptions: {
          refetch: true,
          afterRefetch(_req, _res, session) {
            session.user.foo = 'bar';
            return session;
          }
        }
      });
      const cookieJar = await login(baseUrl);

      const user = await get(baseUrl, '/api/auth/me', { cookieJar });
      expect(user.foo).toEqual('bar');
    });

    test('should throw from the afterRefetch hook', async () => {
      const baseUrl = await setup(withoutApi, {
        profileOptions: {
          refetch: true,
          afterRefetch() {
            throw new Error('some validation error');
          }
        }
      });
      const cookieJar = await login(baseUrl);

      await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrowError('some validation error');
    });
  });
});
