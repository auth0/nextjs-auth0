import { randomBytes } from 'crypto';
import { JWK, JWE } from 'jose';
import { IdTokenClaims } from 'openid-client';
import { setup, teardown } from './fixtures/server';
import { defaultConfig, fromCookieJar, get, toCookieJar } from './fixtures/helpers';
import { encryption as deriveKey } from '../../src/auth0-session/utils/hkdf';
import { makeIdToken } from './fixtures/cert';

const hr = 60 * 60 * 1000;
const day = 24 * hr;
const key = JWK.asKey(deriveKey(defaultConfig.secret as string));

const encrypted = (payload: Partial<IdTokenClaims> = { sub: '__test_sub__' }): string => {
  const epochNow = (Date.now() / 1000) | 0;
  const weekInSeconds = 7 * 24 * 60 * 60;
  return JWE.encrypt(
    JSON.stringify({
      access_token: '__test_access_token__',
      token_type: 'Bearer',
      id_token: makeIdToken(payload),
      refresh_token: '__test_access_token__',
      expires_at: epochNow + weekInSeconds
    }),
    key,
    {
      alg: 'dir',
      enc: 'A256GCM',
      uat: epochNow,
      iat: epochNow,
      exp: epochNow + weekInSeconds
    }
  );
};

describe('CookieStore', () => {
  afterEach(teardown);

  it('should not create a session when there are no cookies', async () => {
    const baseURL = await setup(defaultConfig);
    await expect(get(baseURL, '/session')).rejects.toThrowError('Unauthorized');
  });

  it('should not throw for malformed sessions', async () => {
    const baseURL = await setup(defaultConfig);
    const cookieJar = toCookieJar(
      {
        appSession: '__invalid_identity__'
      },
      baseURL
    );
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should not error with JWEDecryptionFailed when using old secrets', async () => {
    const baseURL = await setup({ ...defaultConfig, secret: ['__invalid_secret__', '__also_invalid__'] });
    const cookieJar = toCookieJar({ appSession: encrypted() }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should get an existing session', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session).toMatchObject({
      access_token: '__test_access_token__',
      token_type: 'Bearer',
      id_token: expect.any(String),
      refresh_token: '__test_access_token__',
      expires_at: expect.any(Number),
      claims: {
        nickname: '__test_nickname__',
        sub: '__test_sub__',
        iss: 'https://op.example.com/',
        aud: '__test_client_id__',
        iat: expect.any(Number),
        exp: expect.any(Number),
        nonce: '__test_nonce__'
      }
    });
  });

  it('should chunk and accept chunked cookies over 4kb', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = encrypted({
      big_claim: randomBytes(2000).toString('base64')
    });
    expect(appSession.length).toBeGreaterThan(4000);
    const cookieJar = toCookieJar(
      {
        'appSession.0': appSession.slice(0, 2000),
        'appSession.1': appSession.slice(2000)
      },
      baseURL
    );
    await get(baseURL, '/session', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(cookies['appSession.0']).toEqual(expect.any(String));
    expect(cookies['appSession.1']).toEqual(expect.any(String));
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session.claims).toHaveProperty('big_claim');
  });

  it('should handle unordered chunked cookies', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = encrypted({ sub: '__chunked_sub__' });
    const cookieJar = toCookieJar(
      {
        'appSession.2': appSession.slice(20),
        foo: 'baz',
        'appSession.0': appSession.slice(0, 10),
        'appSession.1': appSession.slice(10, 20)
      },
      baseURL
    );
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session.claims.sub).toEqual('__chunked_sub__');
  });

  it('should not throw for malformed cookie chunks', async () => {
    const baseURL = await setup(defaultConfig);
    const cookieJar = toCookieJar(
      {
        'appSession.2': 'foo',
        'appSession.0': 'bar'
      },
      baseURL
    );
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should set the default cookie options on http', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      domain: 'localhost',
      httpOnly: true,
      key: 'appSession',
      expires: expect.any(Date),
      path: '/',
      sameSite: 'lax',
      secure: false
    });
  });

  it('should set custom cookie options on http', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { httpOnly: false } } });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      httpOnly: false
    });
  });

  it('should set the default cookie options on https', async () => {
    const baseURL = await setup(defaultConfig, { https: true });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      domain: 'localhost',
      httpOnly: true,
      key: 'appSession',
      expires: expect.any(Date),
      path: '/',
      sameSite: 'lax',
      secure: true
    });
  });

  it('should set custom secure option on https', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { secure: false } } }, { https: true });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      sameSite: 'lax',
      secure: false
    });
  });

  it('should set custom sameSite option on https', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { sameSite: 'none' } } }, { https: true });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      sameSite: 'none',
      secure: true
    });
  });

  it('should use a custom cookie name', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { name: 'myCookie' } });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ myCookie: appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      key: 'myCookie'
    });
  });

  it('should set an ephemeral cookie', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { transient: true } } });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      maxAge: null
    });
  });

  it('should expire after 1 day of inactivity by default', async () => {
    const clock = jest.useFakeTimers('modern');

    const baseURL = await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(25 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
  });

  it('should expire after 7 days regardless of activity by default', async () => {
    const clock = jest.useFakeTimers('modern');
    let days = 7;

    const baseURL = await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    while (days--) {
      jest.advanceTimersByTime(23 * hr);
      await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    }
    jest.advanceTimersByTime(23 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
  });

  it('should expire only after custom absoluteDuration', async () => {
    const clock = jest.useFakeTimers('modern');

    const baseURL = await setup({
      ...defaultConfig,
      session: {
        rolling: false,
        absoluteDuration: (10 * day) / 1000
      }
    });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(9 * day);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(2 * day);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
  });

  it('should expire only after defined rollingDuration period of inactivty', async () => {
    const clock = jest.useFakeTimers('modern');
    const baseURL = await setup({
      ...defaultConfig,
      session: {
        rolling: true,
        absoluteDuration: false,
        rollingDuration: day / 1000,
        cookie: {
          transient: true
        }
      }
    });
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    let days = 30;
    while (days--) {
      jest.advanceTimersByTime(23 * hr);
      await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    }
    jest.advanceTimersByTime(25 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
  });
});
