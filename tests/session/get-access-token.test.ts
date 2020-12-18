import { login, setup, teardown } from '../fixtures/setup';
import { withApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';
import { Session } from '../../src/session';
import { refreshTokenExchange, refreshTokenRotationExchange } from '../fixtures/oidc-nocks';

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
});
