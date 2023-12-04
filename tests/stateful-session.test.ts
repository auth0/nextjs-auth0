import { withoutApi } from './fixtures/default-settings';
import { get, toSignedCookieJar, Store } from './auth0-session/fixtures/helpers';
import { setup, teardown, login } from './fixtures/setup';
import { SessionPayload } from '../src/auth0-session/session/abstract-session';
import { makeIdToken } from './auth0-session/fixtures/cert';
import { ConfigParameters, SessionStore } from '../src/auth0-session';
import { TokenSet } from 'openid-client';

const hr = 60 * 60 * 1000;
const day = 24 * hr;
const epochNow = (Date.now() / 1000) | 0;

const getPayload = async (
  data = { sub: 'dave' },
  iat = epochNow,
  uat = epochNow,
  exp = epochNow + day
): Promise<SessionPayload<any>> => ({
  header: { iat, uat, exp },
  data: { id_token: await makeIdToken(data), user: data }
});

describe('next stateful session', () => {
  let store: SessionStore<TokenSet> & { store: { [key: string]: any } };
  let config: ConfigParameters;

  beforeEach(async () => {
    store = new Store();
    config = { ...withoutApi, session: { store } };
  });

  afterEach(teardown);

  it('should not create a session when there are no cookies', async () => {
    const baseURL = await setup(config);
    await expect(get(baseURL, '/api/auth/me')).resolves.toBe('');
    expect(store.store).toEqual({});
  });

  test('should create a new session', async () => {
    const baseUrl = await setup(config);
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toStrictEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    expect(Object.keys(store)).toHaveLength(1);
  });

  it('should get an existing session', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const profile = await get(baseURL, '/api/auth/me', { cookieJar });
    expect(profile).toMatchObject({
      sub: 'dave'
    });
  });

  it('should delete an existing session', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const profile = await get(baseURL, '/api/auth/me', { cookieJar });
    expect(profile).toMatchObject({
      sub: 'dave'
    });
    expect(Object.values(store.store)).toHaveLength(1);
    expect(cookieJar.getCookieStringSync(baseURL)).toMatch(/^appSession=foo\..+/);
    await get(baseURL, '/api/auth/logout', { cookieJar });
    expect(Object.values(store.store)).toHaveLength(0);
    expect(cookieJar.getCookieStringSync(baseURL)).toEqual('');
  });

  it('uses custom session id generator when provided', async () => {
    const baseUrl = await setup({ ...config, session: { ...config.session, genId: () => 'foo' } });
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toStrictEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
    expect(Object.keys(store)).toHaveLength(1);
    expect(cookieJar.getCookieStringSync(baseUrl)).toMatch(/^appSession=foo\..+/);
  });

  it('should provide current user session to custom session id generator', async () => {
    const genId = jest.fn().mockImplementation((_req, session) => session.user.nickname);
    const baseURL = await setup({ ...config, session: { ...config.session, genId } });
    const cookieJar = await login(baseURL);
    const genIdParams = genId.mock.calls.at(0);
    expect(genIdParams.length).toEqual(2);
    expect('idToken' in genIdParams.at(1)).toBeTruthy();
    expect('user' in genIdParams.at(1)).toBeTruthy();
    expect(cookieJar.getCookieStringSync(baseURL)).toMatch(/^appSession=__test_nickname__\..+/);
  });
});
