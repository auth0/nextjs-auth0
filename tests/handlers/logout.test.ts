import { parse } from 'cookie';
import { parse as parseUrl } from 'url';
import { withoutApi } from '../fixtures/default-settings';
import { get } from '../auth0-session/fixtures/helpers';
import { setup, teardown, login } from '../fixtures/setup';

describe('logout handler', () => {
  afterEach(teardown);

  test('should redirect to auth0', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(statusCode).toBe(302);
    expect(parseUrl(headers['location'], true)).toMatchObject({
      protocol: 'https:',
      host: 'acme.auth0.local',
      query: {
        returnTo: 'http://www.acme.com',
        client_id: '__test_client_id__'
      },
      pathname: '/v2/logout'
    });
  });

  test('should pass logout params to auth0', async () => {
    const baseUrl = await setup(withoutApi, { logoutOptions: { logoutParams: { foo: 'bar' } } });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(statusCode).toBe(302);
    expect(parseUrl(headers['location'], true)).toMatchObject({
      protocol: 'https:',
      host: 'acme.auth0.local',
      query: {
        returnTo: 'http://www.acme.com',
        client_id: '__test_client_id__',
        foo: 'bar'
      },
      pathname: '/v2/logout'
    });
  });

  test('should return to the custom path', async () => {
    const customReturnTo = 'https://www.foo.bar';
    const baseUrl = await setup(withoutApi, {
      logoutOptions: { returnTo: customReturnTo }
    });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(statusCode).toBe(302);
    expect(parseUrl(headers['location'], true).query).toMatchObject({
      returnTo: 'https://www.foo.bar'
    });
  });

  test('should use end_session_endpoint when configured', async () => {
    const baseUrl = await setup(
      { ...withoutApi, auth0Logout: false },
      {
        discoveryOptions: { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
      }
    );
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(statusCode).toBe(302);
    expect(parseUrl(headers['location'])).toMatchObject({
      host: 'my-end-session-endpoint',
      pathname: '/logout'
    });
  });

  test('should use auth0 logout by default even when end_session_endpoint is discovered', async () => {
    const baseUrl = await setup(withoutApi, {
      discoveryOptions: { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    });
    const cookieJar = await login(baseUrl);

    const {
      res: { statusCode, headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(statusCode).toBe(302);
    expect(parseUrl(headers['location'])).toMatchObject({
      host: 'acme.auth0.local',
      pathname: '/v2/logout'
    });
  });

  test('should delete the session', async () => {
    const baseUrl = await setup(withoutApi, {
      discoveryOptions: { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    });
    const cookieJar = await login(baseUrl);

    const {
      res: { headers }
    } = await get(baseUrl, '/api/auth/logout', {
      cookieJar,
      fullResponse: true
    });

    expect(parse(headers['set-cookie'][0])).toMatchObject({
      appSession: '',
      'Max-Age': '0',
      Path: '/'
    });
  });
});
