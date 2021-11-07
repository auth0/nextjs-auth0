import { parse } from 'cookie';
import { parse as parseUrl, URL } from 'url';
import { withoutApi } from '../fixtures/default-settings';
import { setup, teardown, login } from '../fixtures/setup';
import { IncomingMessage } from 'http';

jest.mock('../../src/utils/assert', () => ({
  assertReqRes(req: IncomingMessage) {
    if (req.url?.includes('error=')) {
      const url = new URL(req.url, 'http://example.com');
      throw new Error(url.searchParams.get('error') as string);
    }
  }
}));

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

  test('should allow the returnTo url to be provided in the querystring', async () => {
    const logoutOptions = {
      returnTo: '/bar'
    };
    const baseUrl = await setup(withoutApi, { logoutOptions });
    const cookieJar = await login(baseUrl);
    const { status, headers } = await fetch(`${baseUrl}/api/auth/logout?returnTo=/foo`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });
    expect(status).toBe(302);
    expect(parseUrl(headers.get('location') as string, true).query).toMatchObject({
      returnTo: 'http://www.acme.com/foo'
    });
  });

  test('should take the first returnTo url provided in the querystring', async () => {
    const logoutOptions = {
      returnTo: '/top'
    };
    const baseUrl = await setup(withoutApi, { logoutOptions });
    const cookieJar = await login(baseUrl);
    const { status, headers } = await fetch(`${baseUrl}/api/auth/logout?returnTo=/foo&returnTo=/bar`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });
    expect(status).toBe(302);
    expect(parseUrl(headers.get('location') as string, true).query).toMatchObject({
      returnTo: 'http://www.acme.com/foo'
    });
  });

  test('should not allow absolute urls to be provided in the querystring', async () => {
    const logoutOptions = {
      returnTo: '/default-redirect'
    };
    const baseUrl = await setup(withoutApi, { logoutOptions });
    const cookieJar = await login(baseUrl);

    const res = await fetch(`${baseUrl}/api/auth/logout?returnTo=https://www.google.com`, {
      redirect: 'manual',
      headers: {
        cookie: cookieJar.getCookieStringSync(baseUrl)
      }
    });
    expect(res.status).toBe(500);
    expect(await res.text()).toEqual('Invalid value provided for returnTo, must be a relative url');
  });

  test('should escape html in errors', async () => {
    const baseUrl = await setup(withoutApi);

    const res = await fetch(`${baseUrl}/api/auth/logout?error=%3Cscript%3Ealert(%27xss%27)%3C%2Fscript%3E`);

    expect(await res.text()).toEqual('&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;');
  });
});
