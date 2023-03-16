import { TokenSet } from 'openid-client';
import { setup, teardown } from '../fixtures/server';
import { defaultConfig, get, post, toSignedCookieJar } from '../fixtures/helpers';
import { ConfigParameters, SessionStore } from '../../../src/auth0-session';
import { SessionPayload } from '../../../src/auth0-session/session/abstract-session';
import { makeIdToken } from '../fixtures/cert';
import { CookieJar } from 'tough-cookie';
import { encodeState } from '../../../src/auth0-session/utils/encoding';

const hr = 60 * 60 * 1000;
const day = 24 * hr;
const epochNow = (Date.now() / 1000) | 0;

const login = async (baseURL: string, existingSession?: { appSession: string }): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: 'https://example.org' });
  const cookieJar = await toSignedCookieJar({ state, nonce, ...existingSession }, baseURL);
  await post(baseURL, '/callback', {
    body: {
      state,
      id_token: await makeIdToken({ nonce })
    },
    cookieJar
  });
  return cookieJar;
};

class Store {
  public store: { [key: string]: any };
  constructor() {
    this.store = {};
  }
  get(id: string) {
    return Promise.resolve(this.store[id]);
  }
  async set(id: string, val: any) {
    this.store[id] = val;
    await Promise.resolve();
  }
  async delete(id: string) {
    delete this.store[id];
    await Promise.resolve();
  }
}

const getPayload = async (
  data = { sub: 'dave' },
  iat = epochNow,
  uat = epochNow,
  exp = epochNow + day
): Promise<SessionPayload<any>> => ({
  header: { iat, uat, exp },
  data: { id_token: await makeIdToken(data) }
});

describe('StatefulSession', () => {
  let store: SessionStore<TokenSet> & { store: { [key: string]: any } };
  let config: ConfigParameters;
  let count: number;

  beforeEach(async () => {
    store = new Store();
    count = 0;
    config = { ...defaultConfig, session: { store, genId: () => count } };
  });

  afterEach(teardown);

  it('should not create a session when there are no cookies', async () => {
    const baseURL = await setup(config);
    await expect(get(baseURL, '/session')).rejects.toThrowError('Unauthorized');
    expect(store.store).toEqual({});
  });

  it('should get an existing session', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const [cookie] = await cookieJar.getCookies(baseURL);
    const expires = cookie.expires;
    await get(baseURL, '/session', { cookieJar });
    const [updatedCookie] = await cookieJar.getCookies(baseURL);
    expect(updatedCookie.expires > expires);
  });

  it('should update the cookie expiry when setting an existing session', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session).toMatchObject({
      id_token: expect.any(String),
      claims: {
        nickname: '__test_nickname__',
        sub: 'dave',
        iss: 'https://op.example.com/',
        aud: '__test_client_id__',
        iat: expect.any(Number),
        exp: expect.any(Number),
        nonce: '__test_nonce__'
      }
    });
  });

  it('should create a new session', async () => {
    const baseURL = await setup(config);
    expect(Object.values(store.store)).toHaveLength(0);
    const cookieJar = await login(baseURL);
    const sessions = Object.values(store.store);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      header: { iat: expect.any(Number), uat: expect.any(Number), exp: expect.any(Number) },
      data: expect.any(TokenSet)
    });
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session).toMatchObject({
      id_token: expect.any(String),
      claims: {
        sub: '__test_sub__'
      }
    });
  });

  it('should delete an existing session', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session).toMatchObject({
      id_token: expect.any(String),
      claims: {
        sub: 'dave'
      }
    });
    expect(Object.values(store.store)).toHaveLength(1);
    expect(cookieJar.getCookieStringSync(baseURL)).toMatch(/^appSession=.+/);
    await get(baseURL, '/logout', { cookieJar });
    expect(Object.values(store.store)).toHaveLength(0);
    expect(cookieJar.getCookieStringSync(baseURL)).toEqual('');
  });

  it('uses custom session id generator when provided', async () => {
    const baseURL = await setup({ ...config, session: { ...config.session, genId: () => 'foobar' } });
    expect(Object.values(store.store)).toHaveLength(0);
    const cookieJar = await login(baseURL);
    const sessions = Object.values(store.store);
    expect(sessions).toHaveLength(1);
    expect(cookieJar.getCookieStringSync(baseURL)).toMatch(/^appSession=foobar\..+/);
  });

  it('should regenerate the session when a new user is logging in over an existing user', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup(config);
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    const sessionIds = Object.keys(store.store);
    expect(sessionIds).toHaveLength(1);
    expect(session).toMatchObject({
      id_token: expect.any(String),
      claims: {
        sub: 'dave'
      }
    });
    expect(store.store).toHaveProperty('foo');
    await login(baseURL, { appSession: 'foo' });
    expect(store.store).not.toHaveProperty('foo');
    const newSessionIds = Object.keys(store.store);
    expect(newSessionIds).toHaveLength(1);
    const [oldSessionId] = sessionIds;
    const [newSessionId] = newSessionIds;
    expect(oldSessionId).toBe('foo');
    expect(newSessionId).not.toBe('foo');
    expect(newSessionId).toBeTruthy();
  });

  it('should rotate signing secrets', async () => {
    await store.set('foo', await getPayload());
    const baseURL = await setup({ ...config, secret: ['__test_session_secret__', '__old_session_secret__'] });
    const cookieJar = await toSignedCookieJar({ appSession: 'foo' }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session).toMatchObject({
      id_token: expect.any(String),
      claims: {
        sub: 'dave'
      }
    });
  });
});
