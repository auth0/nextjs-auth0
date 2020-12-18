import { parse } from 'url';
import { CookieJar } from 'tough-cookie';
import { SessionResponse, setup, teardown } from '../fixtures/server';
import { toSignedCookieJar, defaultConfig, get, post, fromCookieJar } from '../fixtures/helpers';
import { makeIdToken } from '../fixtures/cert';
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

  it('should delete session cookies on logout', async () => {
    const baseURL = await setup({ ...defaultConfig, idpLogout: false });
    const cookieJar = await login(baseURL);
    cookieJar.setCookieSync('foo=bar', baseURL);

    await get(baseURL, '/session', { cookieJar });
    expect(fromCookieJar(cookieJar, baseURL)).toMatchObject({
      appSession: expect.any(String),
      foo: 'bar'
    });

    await get(baseURL, '/logout', { cookieJar, fullResponse: true });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(cookies).toHaveProperty('foo');
    expect(cookies).not.toHaveProperty('appSession');
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
});
