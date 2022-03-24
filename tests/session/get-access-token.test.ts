import { login, setup, teardown } from '../fixtures/setup';
import { withApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';
import { Session } from '../../src';
import { refreshTokenExchange, refreshTokenRotationExchange } from '../fixtures/oidc-nocks';
import { makeIdToken } from '../auth0-session/fixtures/cert';
import nock from 'nock';

describe('get access token', () => {
  afterEach(teardown);

  test('should fail if the session is missing', async () => {
    const baseUrl = await setup(withApi);

    await expect(get(baseUrl, '/api/access-token')).rejects.toThrow('The user does not have a valid session.');
  });

  test('should fail if access_token and refresh_token are missing', async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          delete session.accessToken;
          delete session.refreshToken;
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'The user does not have a valid access token.'
    );
  });

  test('should fail if access_token expiry is missing', async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          delete session.accessTokenExpiresAt;
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'Expiration information for the access token is not available. The user will need to sign in again.'
    );
  });

  test('should fail if access_token scope is missing', async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          delete session.accessTokenScope;
          return session;
        }
      },
      getAccessTokenOptions: {
        scopes: ['read:foo']
      }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'An access token with the requested scopes could not be provided. The user will need to sign in again.'
    );
  });

  test("should fail if access_token scope doesn't match requested scope", async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          session.accessTokenScope = 'read:bar';
          return session;
        }
      },
      getAccessTokenOptions: {
        scopes: ['read:foo']
      }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'Could not retrieve an access token with scopes "read:foo". The user will need to sign in again.'
    );
  });

  test('should fail if the access token is expired', async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          delete session.refreshToken;
          session.accessTokenExpiresAt = -60;
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'The access token expired and a refresh token is not available. The user will need to sign in again.'
    );
  });

  test('should fail if you try to refresh the access token without a refresh token', async () => {
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          delete session.refreshToken;
          return session;
        }
      },
      getAccessTokenOptions: { refresh: true }
    });
    const cookieJar = await login(baseUrl);
    await expect(get(baseUrl, '/api/access-token', { cookieJar })).rejects.toThrow(
      'A refresh token is required to refresh the access token, but none is present.'
    );
  });

  test('should return an access token', async () => {
    const baseUrl = await setup(withApi);
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('eyJz93a...k4laUWw');
  });

  test('should retrieve a new access token if the old one is expired and update the profile', async () => {
    refreshTokenExchange(
      withApi,
      'GEbRxBN...edjnXbL',
      {
        email: 'john@test.com',
        name: 'john doe',
        sub: '123'
      },
      'new-token'
    );
    const baseUrl = await setup(withApi, {
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          session.accessTokenExpiresAt = -60;
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    const { refreshToken } = await get(baseUrl, '/api/session', { cookieJar });
    expect(refreshToken).toEqual('GEbRxBN...edjnXbL');
  });

  test('should retrieve a new access token if force refresh is set', async () => {
    refreshTokenExchange(
      withApi,
      'GEbRxBN...edjnXbL',
      {
        email: 'john@test.com',
        name: 'john doe',
        sub: '123'
      },
      'new-token'
    );
    const baseUrl = await setup(withApi, { getAccessTokenOptions: { refresh: true } });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    const { refreshToken } = await get(baseUrl, '/api/session', { cookieJar });
    expect(refreshToken).toEqual('GEbRxBN...edjnXbL');
  });

  test('should retrieve a new access token and rotate the refresh token', async () => {
    refreshTokenRotationExchange(
      withApi,
      'GEbRxBN...edjnXbL',
      {
        email: 'john@test.com',
        name: 'john doe',
        sub: '123'
      },
      'new-token',
      'new-refresh-token'
    );
    const baseUrl = await setup(withApi, { getAccessTokenOptions: { refresh: true } });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    const { refreshToken } = await get(baseUrl, '/api/session', { cookieJar });
    expect(refreshToken).toEqual('new-refresh-token');
  });

  test('should return an access token with the given scopes', async () => {
    const baseUrl = await setup(withApi, { getAccessTokenOptions: { scopes: ['read:foo'] } });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('eyJz93a...k4laUWw');
  });

  test('should not overwrite custom session properties when applying a new access token', async () => {
    refreshTokenExchange(
      withApi,
      'GEbRxBN...edjnXbL',
      {
        email: 'john@test.com',
        name: 'john doe',
        sub: '123'
      },
      'new-token'
    );
    const baseUrl = await setup(withApi, {
      getAccessTokenOptions: { refresh: true },
      callbackOptions: {
        afterCallback: (_req, _res, session): Session => {
          session.foo = 'bar';
          session.user.bar = 'baz';
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    const session = await get(baseUrl, '/api/session', { cookieJar });
    expect(session).toMatchObject({
      foo: 'bar',
      accessToken: 'new-token',
      refreshToken: 'GEbRxBN...edjnXbL',
      user: {
        nickname: '__test_nickname__',
        email: 'john@test.com',
        name: 'john doe',
        sub: '123',
        bar: 'baz'
      }
    });
  });

  test('should retrieve a new access token and update the session based on afterRefresh', async () => {
    refreshTokenExchange(
      withApi,
      'GEbRxBN...edjnXbL',
      {
        email: 'john@test.com',
        name: 'john doe',
        sub: '123'
      },
      'new-token'
    );
    const baseUrl = await setup(withApi, {
      getAccessTokenOptions: {
        refresh: true,
        afterRefresh(_req, _res, session) {
          delete session.idToken;
          return session;
        }
      }
    });
    const cookieJar = await login(baseUrl);
    const { idToken } = await get(baseUrl, '/api/session', { cookieJar });
    expect(idToken).not.toBeUndefined();
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    const { idToken: newIdToken } = await get(baseUrl, '/api/session', { cookieJar });
    expect(newIdToken).toBeUndefined();
  });

  test('should pass custom auth params in refresh grant request body', async () => {
    const idToken = makeIdToken({
      iss: `${withApi.issuerBaseURL}/`,
      aud: withApi.clientID,
      email: 'john@test.com',
      name: 'john doe',
      sub: '123'
    });

    const spy = jest.fn();
    nock(`${withApi.issuerBaseURL}`)
      .post('/oauth/token', /grant_type=refresh_token/)
      .reply(200, (_, body) => {
        spy(body);
        return {
          access_token: 'new-token',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 750,
          scope: 'read:foo write:foo'
        };
      });

    const baseUrl = await setup(withApi, {
      getAccessTokenOptions: { refresh: true, authorizationParams: { baz: 'qux' } }
    });
    const cookieJar = await login(baseUrl);
    const { accessToken } = await get(baseUrl, '/api/access-token', { cookieJar });
    expect(accessToken).toEqual('new-token');
    expect(spy).toHaveBeenCalledWith(expect.stringContaining('baz=qux'));
  });
});
