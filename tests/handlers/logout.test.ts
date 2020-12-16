import { parse } from 'cookie';
import { parse as parseUrl } from 'url';
import { start, stop } from '../helpers/server';
import { LogoutOptions } from '../../src';
import { ConfigParameters } from '../../src/auth0-session';
import { withoutApi } from '../helpers/default-settings';
import { discovery, jwksEndpoint } from '../helpers/oidc-nocks';
import { CookieJar } from 'tough-cookie';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { post, toSignedCookieJar } from '../auth0-session/fixture/helpers';
import { jwks, makeIdToken } from '../auth0-session/fixture/cert';
import { initAuth0 } from '../../src';

const login = async (baseUrl: string, config: ConfigParameters): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: '/' });
  const cookieJar = toSignedCookieJar({ state, nonce }, baseUrl);
  await post(baseUrl, '/api/auth/callback', {
    fullResponse: true,
    body: {
      state,
      id_token: makeIdToken({ nonce, iss: `${config.issuerBaseURL}/` })
    },
    cookieJar
  });
  return cookieJar;
};

const setupHandler = async (
  config: ConfigParameters,
  logoutOptions?: LogoutOptions,
  discoveryOptions?: any
): Promise<string> => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  const { handleAuth, handleLogout } = await initAuth0(config);
  (global as any).handleAuth = handleAuth.bind(null, {
    async logout(req, res) {
      try {
        await handleLogout(req, res, logoutOptions);
      } catch (error) {
        res.status(error.status || 500).end(error.message);
      }
    }
  });
  return start();
};

describe('logout handler', () => {
  afterEach(async () => {
    jest.resetModules();
    await stop();
  });

  test('should redirect to the identity provider', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const cookieJar = await login(baseUrl, withoutApi);

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
    const baseUrl = await setupHandler(withoutApi, {
      returnTo: customReturnTo
    });
    const cookieJar = await login(baseUrl, withoutApi);

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
    const baseUrl = await setupHandler(
      withoutApi,
      {},
      { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    );
    const cookieJar = await login(baseUrl, withoutApi);

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
    const baseUrl = await setupHandler(
      withoutApi,
      {},
      { end_session_endpoint: 'https://my-end-session-endpoint/logout' }
    );
    const cookieJar = await login(baseUrl, withoutApi);

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
