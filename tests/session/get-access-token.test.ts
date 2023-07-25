/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import { NextRequest, NextResponse } from 'next/server';
import nock from 'nock';
import { withApi } from '../fixtures/default-settings';
import { AccessTokenRequest, Session } from '../../src';
import { refreshTokenExchange } from '../fixtures/oidc-nocks';
import {
  getResponse,
  GetResponseOpts,
  LoginOpts,
  login as appRouterLogin,
  mockFetch,
  initAuth0
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
      async 'access-token'(req: NextRequest) {
        const res = new NextResponse();
        const at = await auth0Instance.getAccessToken(req, res, getAccessTokenOpts);
        const session = await auth0Instance.getSession(req, res);
        return NextResponse.json({ at, session }, res);
      }
    },
    cookies,
    clearNock: false,
    ...getResOpts
  }).finally(() => nock.cleanAll());
};

describe('get access token (api route)', () => {
  beforeEach(mockFetch);

  test('should fail if the session is missing', async () => {
    await expect(getAccessTokenResponse()).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/The user does not have a valid session/)
    });
  });

  test('should fail if access_token and refresh_token are missing', async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              delete session.accessToken;
              delete session.refreshToken;
              return session;
            }
          }
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/The user does not have a valid access token/)
    });
  });

  test('should fail if access_token expiry is missing', async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              delete session.accessTokenExpiresAt;
              return session;
            }
          }
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/Expiration information for the access token is not available/)
    });
  });

  test('should fail if access_token scope is missing', async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              delete session.accessTokenScope;
              return session;
            }
          }
        },
        getAccessTokenOpts: {
          scopes: ['read:foo']
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/An access token with the requested scopes could not be provided/)
    });
  });

  test("should fail if access_token scope doesn't match requested scope", async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              return { ...session, accessTokenScope: 'read:bar' };
            }
          }
        },
        getAccessTokenOpts: {
          scopes: ['read:foo']
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/Could not retrieve an access token with scopes "read:foo"/)
    });
  });

  test('should fail if the access token is expired', async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              delete session.refreshToken;
              return { ...session, accessTokenExpiresAt: -60 };
            }
          }
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/The access token expired and a refresh token is not available/)
    });
  });

  test('should fail if you try to refresh the access token without a refresh token', async () => {
    await expect(
      getAccessTokenResponse({
        authenticated: true,
        loginOpts: {
          callbackOpts: {
            afterCallback(_req: NextRequest, session: Session) {
              delete session.refreshToken;
              return session;
            }
          }
        },
        getAccessTokenOpts: { refresh: true }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/A refresh token is required to refresh the access token, but none is present/)
    });
  });

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

  test('should retrieve a new access token if force refresh is set', async () => {
    const res = await getAccessTokenResponse({
      authenticated: true,
      getAccessTokenOpts: { refresh: true }
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

  test('should fail when the refresh grant request fails', async () => {
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
