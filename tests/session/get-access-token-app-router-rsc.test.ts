import { NextRequest, NextResponse } from 'next/server';
import nock from 'nock';
import { withApi } from '../fixtures/default-settings';
import { AccessTokenRequest, initAuth0, Session } from '../../src';
import { refreshTokenExchange } from '../fixtures/oidc-nocks';
import {
  getResponse,
  GetResponseOpts,
  LoginOpts,
  login as appRouterLogin,
  mockFetch
} from '../fixtures/app-router-helpers';

const getAccessTokenResponse = async ({
  authenticated = false,
  getResOpts = {},
  loginOpts = {},
  getAccessTokenOpts
}: {
  authenticated?: boolean;
  getResOpts?: Omit<GetResponseOpts, 'url'>;
  loginOpts?: LoginOpts;
  getAccessTokenOpts?: AccessTokenRequest;
} = {}) => {
  const auth0Instance = initAuth0(withApi);
  let cookies: { appSession?: string } = {};
  if (authenticated) {
    const loginRes = await appRouterLogin(loginOpts);
    cookies.appSession = loginRes.cookies.get('appSession').value;
    jest.doMock('next/headers', () => ({ cookies: () => loginRes.cookies }));
  }
  await refreshTokenExchange(
    withApi,
    'GEbRxBN...edjnXbL',
    {
      email: 'john@test.com',
      name: 'john doe',
      sub: '123'
    },
    'new-token'
  );
  return getResponse({
    auth0Instance,
    url: '/api/auth/access-token',
    extraHandlers: {
      async 'access-token'() {
        const at = await auth0Instance.getAccessToken(getAccessTokenOpts);
        const session = await auth0Instance.getSession();
        return NextResponse.json({ at, session });
      }
    },
    cookies,
    clearNock: false,
    ...getResOpts
  }).finally(() => nock.cleanAll());
};

describe('get access token (app router rsc)', () => {
  beforeEach(mockFetch);

  test('should return an access token', async () => {
    const res = await getAccessTokenResponse({
      authenticated: true
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      at: { accessToken: 'eyJz93a...k4laUWw' }
    });
  });

  test('should retrieve a new access token if the old one is expired and update the profile', async () => {
    const res = await getAccessTokenResponse({
      authenticated: true,
      loginOpts: {
        callbackOpts: {
          afterCallback(_req: NextRequest, session: Session) {
            return { ...session, accessTokenExpiresAt: -60 };
          }
        }
      }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      at: { accessToken: 'new-token' },
      session: expect.objectContaining({ user: expect.objectContaining({ email: 'john@test.com' }) })
    });
  });

  test('should retrieve a new access token and update the session based on afterRefresh', async () => {
    const res = await getAccessTokenResponse({
      authenticated: true,
      getAccessTokenOpts: {
        refresh: true,
        afterRefresh(_req, _res, session) {
          return { ...session, foo: 'baz' };
        }
      }
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      at: { accessToken: 'new-token' },
      session: expect.objectContaining({ foo: 'baz' })
    });
  });
});
