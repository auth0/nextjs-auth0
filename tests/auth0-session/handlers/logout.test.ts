import { parse } from 'url';
import { CookieJar } from 'tough-cookie';
import { SessionResponse, setup, teardown } from '../fixture/server';
import { toSignedCookieJar, defaultConfig, get, post } from '../fixture/helpers';
import { makeIdToken } from '../fixture/cert';
import { encodeState } from '../../../src/auth0-session/hooks/get-login-state';

const login = async (baseURL: string): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: 'https://example.org' });
  const cookieJar = toSignedCookieJar({ state, nonce }, baseURL);
  await post(baseURL, '/callback', {
    body: {
      state,
      id_token: makeIdToken({ nonce })
    },
    cookieJar
  });
  return cookieJar;
};

describe('logout route', () => {
  afterEach(teardown);

  it('should perform a local logout', async () => {
    const baseURL = await setup({ ...defaultConfig, idpLogout: false });
    const cookieJar = await login(baseURL);

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session.id_token).toBeTruthy();

    const { res } = await get(baseURL, '/logout', { cookieJar, fullResponse: true });

    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(baseURL);
  });

  it('should perform a distributed logout', async () => {
    const baseURL = await setup({ ...defaultConfig, idpLogout: true });
    const cookieJar = await login(baseURL);

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session.id_token).toBeTruthy();

    const { res } = await get(baseURL, '/logout', { cookieJar, fullResponse: true });

    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');

    expect(res.statusCode).toEqual(302);
    const redirect = parse(res.headers.location, true);
    expect(redirect).toMatchObject({
      hostname: 'op.example.com',
      pathname: '/session/end',
      protocol: 'https:',
      query: expect.objectContaining({ post_logout_redirect_uri: baseURL })
    });
  });

  it('should perform an auth0 logout', async () => {
    const baseURL = await setup({
      ...defaultConfig,
      issuerBaseURL: 'https://test.eu.auth0.com/',
      idpLogout: true,
      auth0Logout: true
    });
    const nonce = '__test_nonce__';
    const state = encodeState({ returnTo: 'https://example.org' });
    const cookieJar = toSignedCookieJar({ state, nonce }, baseURL);
    await post(baseURL, '/callback', {
      body: {
        state,
        id_token: makeIdToken({ nonce, iss: 'https://test.eu.auth0.com/' })
      },
      cookieJar
    });

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session.id_token).toBeTruthy();

    const { res } = await get(baseURL, '/logout', { cookieJar, fullResponse: true });

    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');

    expect(res.statusCode).toEqual(302);
    const redirect = parse(res.headers.location, true);
    expect(redirect).toMatchObject({
      hostname: 'test.eu.auth0.com',
      pathname: '/v2/logout',
      protocol: 'https:',
      query: expect.objectContaining({
        client_id: '__test_client_id__',
        returnTo: baseURL
      })
    });
  });

  it('should redirect to postLogoutRedirect', async () => {
    const postLogoutRedirect = 'https://example.com/post-logout';
    const baseURL = await setup({ ...defaultConfig, routes: { postLogoutRedirect } });
    const cookieJar = await login(baseURL);

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session.id_token).toBeTruthy();

    const { res } = await get(baseURL, '/logout', { cookieJar, fullResponse: true });

    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(postLogoutRedirect);
  });

  it('should redirect to the specified returnTo', async () => {
    const returnTo = 'https://example.com/return-to';
    const baseURL = await setup(defaultConfig, { logoutOptions: { returnTo } });
    const cookieJar = await login(baseURL);

    const session: SessionResponse = await get(baseURL, '/session', { cookieJar });
    expect(session.id_token).toBeTruthy();

    const { res } = await get(baseURL, '/logout', { cookieJar, fullResponse: true });

    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(returnTo);
  });

  it('should redirect when already logged out', async () => {
    const returnTo = 'https://example.com/return-to';
    const baseURL = await setup(defaultConfig, { logoutOptions: { returnTo } });

    const { res } = await get(baseURL, '/logout', { fullResponse: true });

    expect(res.statusCode).toEqual(302);
    expect(res.headers.location).toEqual(returnTo);
  });
  //
  // it('should logout when scoped to a sub path', async () => {
  //   server = await createServer(
  //     auth({
  //       ...defaultConfig,
  //       session: {
  //         cookie: {
  //           path: '/foo',
  //         },
  //       },
  //     }),
  //     null,
  //     '/foo'
  //   );
  //   const baseUrl = 'http://localhost:3000/foo';
  //
  //   const { jar, session: loggedInSession } = await login(baseUrl);
  //   assert.ok(loggedInSession.id_token);
  //   const sessionCookie = jar
  //     .getCookies('http://localhost:3000/foo')
  //     .find(({ key }) => key === 'appSession');
  //   assert.equal(sessionCookie.path, '/foo');
  //   const { session: loggedOutSession } = await logout(jar, baseUrl);
  //   assert.notOk(loggedOutSession.id_token);
  // });
});
