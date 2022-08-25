import nock from 'nock';
import { withApi, withoutApi } from '../fixtures/default-settings';
import { refreshTokenRotationExchange, userInfo } from '../fixtures/oidc-nocks';
import { get } from '../auth0-session/fixtures/helpers';
import { setup, teardown, login } from '../fixtures/setup';
import { Session, AfterCallback } from '../../src';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import { IncomingMessage } from 'http';
import { URL } from 'url';

jest.mock('../../src/utils/assert', () => ({
  assertReqRes(req: IncomingMessage) {
    if (req.url?.includes('error=')) {
      const url = new URL(req.url, 'http://example.com');
      throw new Error(url.searchParams.get('error') as string);
    }
  }
}));

describe('profile handler', () => {
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

  test('should throw if re-fetching with no Access Token', async () => {
    const afterCallback: AfterCallback = (_req, _res, session: Session): Session => {
      delete session.accessToken;
      return session;
    };
    const baseUrl = await setup(withoutApi, { profileOptions: { refetch: true }, callbackOptions: { afterCallback } });
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
    const afterCallback: AfterCallback = (_req, _res, session: Session): Session => {
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
        id_token: makeIdToken({ iss: 'https://acme.auth0.local/' }),
        token_type: 'Bearer',
        expires_in: 750,
        scope: 'read:foo write:foo'
      });
    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrow(
      'No access token available to refetch the profile'
    );
  });

  test('should refetch the user and preserve new tokens', async () => {
    const afterCallback: AfterCallback = (_req, _res, session: Session): Session => {
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
    refreshTokenRotationExchange(withApi, 'GEbRxBN...edjnXbL', {}, 'new-access-token', 'new-refresh-token');
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

  test('should escape html in error message', async () => {
    const baseUrl = await setup(withoutApi);
    const res = await fetch(`${baseUrl}/api/auth/me?error=%3Cscript%3Ealert(%27xss%27)%3C%2Fscript%3E`);

    expect(await res.text()).toEqual(
      'Profile handler failed. CAUSE: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;'
    );
  });
});
