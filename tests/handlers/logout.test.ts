import { parse } from 'cookie';
import { parse as parseUrl } from 'url';
import { withoutApi } from '../helpers/default-settings';
import { setup, teardown, login } from '../helpers/setup';

describe('logout handler', () => {
  afterEach(teardown);

  test('should redirect to the identity provider', async () => {
    const baseUrl = await setup(withoutApi);
    const cookieJar = await login(baseUrl);

    const { status, headers } = await fetch(`${baseUrl}/api/auth/logout`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });

    expect(status).toBe(302);
    expect(parseUrl(headers.get('location') as string, true)).toMatchObject({
      protocol: 'https:',
      host: 'acme.auth0.local',
      query: {
        returnTo: 'http://www.acme.com',
        client_id: '__test_client_id__'
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

    const { status, headers } = await fetch(`${baseUrl}/api/auth/logout`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });

    expect(status).toBe(302);
    expect(parseUrl(headers.get('location') as string, true).query).toMatchObject({
      returnTo: 'https://www.foo.bar'
    });
  });

  test('should use end_session_endpoint if available', async () => {
    const baseUrl = await setup(withoutApi, {
      discoveryOptions: { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    });
    const cookieJar = await login(baseUrl);

    const { status, headers } = await fetch(`${baseUrl}/api/auth/logout`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });

    expect(status).toBe(302);
    expect(parseUrl(headers.get('location') as string)).toMatchObject({
      host: 'my-end-session-endpoint',
      pathname: '/logout'
    });
  });

  test('should delete the session', async () => {
    const baseUrl = await setup(withoutApi, {
      discoveryOptions: { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    });
    const cookieJar = await login(baseUrl);

    const res = await fetch(`${baseUrl}/api/auth/logout`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });

    expect(parse(res.headers.get('set-cookie') as string)).toMatchObject({
      appSession: '',
      'Max-Age': '0',
      Path: '/'
    });
  });
});
