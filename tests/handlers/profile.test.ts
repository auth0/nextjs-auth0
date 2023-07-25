/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import nock from 'nock';
import { withApi } from '../fixtures/default-settings';
import { refreshTokenRotationExchange } from '../fixtures/oidc-nocks';
import { Session } from '../../src';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import {
  getResponse,
  login as appRouterLogin,
  getSession as appRouterGetSession,
  mockFetch
} from '../fixtures/app-router-helpers';
import { NextRequest } from 'next/server';

describe('profile handler (app router)', () => {
  beforeEach(mockFetch);

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
      profileOpts: { refetch: true },
      userInfoPayload: { sub: 'foo' }
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
      userInfoPayload: { foo: 'bar', sub: 'foo' }
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
    nock.cleanAll();
    nock(`${withApi.issuerBaseURL}`)
      .post('/oauth/token', (body) => {
        //`grant_type=refresh_token&refresh_token=GEbRxBN...edjnXbL`
        return body.grant_type === 'refresh_token' && body.refresh_token === 'GEbRxBN...edjnXbL';
      })
      .reply(200, {
        id_token: await makeIdToken({ iss: 'https://acme.auth0.local/' }),
        token_type: 'Bearer',
        expires_in: 750,
        scope: 'read:foo write:foo'
      });

    const res = await getResponse({
      url: '/api/auth/me',
      cookies: { appSession: loginRes.cookies.get('appSession').value },
      profileOpts: { refetch: true },
      userInfoPayload: { foo: 'bar' },
      clearNock: false,
      userInfoToken: 'new-access-token'
    });
    expect(res.status).toBe(500);
    expect(res.statusText).toMatch(
      /No access token available to refetch the profile|"access_token" property must be a non-empty string/
    );
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
    nock.cleanAll();
    await refreshTokenRotationExchange(withApi, 'GEbRxBN...edjnXbL', {}, 'new-access-token', 'new-refresh-token');
    const res = await getResponse({
      url: '/api/auth/me',
      cookies: { appSession: loginRes.cookies.get('appSession').value },
      profileOpts: { refetch: true },
      userInfoPayload: { foo: 'bar', sub: 'foo' },
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
      userInfoPayload: { sub: 'foo' },
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
        userInfoPayload: { sub: 'foo' },
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
