import { randomBytes } from 'crypto';
import * as jose from 'jose';
import { IdTokenClaims } from 'openid-client';
import { setup, teardown } from './fixtures/server';
import { defaultConfig, fromCookieJar, get, toCookieJar } from './fixtures/helpers';
import { encryption as deriveKey } from '../../src/auth0-session/utils/hkdf';
import { makeIdToken } from './fixtures/cert';

const hr = 60 * 60 * 1000;
const day = 24 * hr;

const encrypted = async (claims: Partial<IdTokenClaims> = { sub: '__test_sub__' }): Promise<string> => {
  const key = await deriveKey(defaultConfig.secret as string);
  const epochNow = (Date.now() / 1000) | 0;
  const weekInSeconds = 7 * 24 * 60 * 60;
  const payload = {
    access_token: '__test_access_token__',
    token_type: 'Bearer',
    id_token: await makeIdToken(claims),
    refresh_token: '__test_access_token__',
    expires_at: epochNow + weekInSeconds
  };
  return new jose.EncryptJWT({ ...payload })
    .setProtectedHeader({
      alg: 'dir',
      enc: 'A256GCM',
      uat: epochNow,
      iat: epochNow,
      exp: epochNow + weekInSeconds
    })
    .encrypt(key);
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
    const cookieJar = toCookieJar({ appSession: await encrypted() }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should get an existing session', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted();
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
    const appSession = await encrypted({
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

  it('should limit total cookie size to 4096 Bytes', async () => {
    const path =
      '/some-really-really-really-really-really-really-really-really-really-really-really-really-really-long-path';
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { path } } });
    const appSession = await encrypted({
      big_claim: randomBytes(5000).toString('base64')
    });
    expect(appSession.length).toBeGreaterThan(4096);
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const cookies: { [key: string]: string } = cookieJar
      .getCookiesSync(`${baseURL}${path}`)
      .reduce((obj, value) => Object.assign(obj, { [value.key]: value + '' }), {});
    expect(cookies['appSession.0']).toHaveLength(4096);
    expect(cookies['appSession.1']).toHaveLength(4096);
    expect(cookies['appSession.2']).toHaveLength(4096);
    expect(cookies['appSession.3'].length).toBeLessThan(4096);
  });

  it('should handle unordered chunked cookies', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted({ sub: '__chunked_sub__' });
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

  it('should clean up single cookie when switching to chunked', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted({
      big_claim: randomBytes(2000).toString('base64')
    });
    expect(appSession.length).toBeGreaterThan(4000);
    const cookieJar = toCookieJar({ appSession }, baseURL);
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session.claims).toHaveProperty('big_claim');
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(cookies).toHaveProperty(['appSession.0']);
    expect(cookies).not.toHaveProperty('appSession');
  });

  it('should clean up chunked cookies when switching to a single cookie', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted({ sub: 'foo' });
    const cookieJar = toCookieJar(
      {
        'appSession.0': appSession.slice(0, 100),
        'appSession.1': appSession.slice(100)
      },
      baseURL
    );
    const session = await get(baseURL, '/session', { cookieJar });
    expect(session.claims).toHaveProperty('sub');
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(cookies).toHaveProperty('appSession');
    expect(cookies).not.toHaveProperty(['appSession.0']);
  });

  it('should set the default cookie options on http', async () => {
    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted();
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
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      httpOnly: false
    });
  });

  it('should set the default cookie options on https', async () => {
    const baseURL = await setup(defaultConfig, { https: true });
    const appSession = await encrypted();
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
    const appSession = await encrypted();
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
    const appSession = await encrypted();
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
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ myCookie: appSession }, baseURL);
    await get(baseURL, '/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(baseURL);
    expect(cookie).toMatchObject({
      key: 'myCookie'
    });
  });

  it('should set an ephemeral cookie', async () => {
    const baseURL = await setup({ ...defaultConfig, session: { cookie: { transient: true } } });
    const appSession = await encrypted();
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
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(25 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
    jest.useRealTimers();
  });

  it('should expire after 7 days regardless of activity by default', async () => {
    const clock = jest.useFakeTimers('modern');
    let days = 7;

    const baseURL = await setup(defaultConfig);
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    while (days--) {
      jest.advanceTimersByTime(23 * hr);
      await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    }
    jest.advanceTimersByTime(23 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
    jest.useRealTimers();
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
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(9 * day);
    await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    jest.advanceTimersByTime(2 * day);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
    jest.useRealTimers();
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
    const appSession = await encrypted();
    const cookieJar = toCookieJar({ appSession }, baseURL);
    let days = 30;
    while (days--) {
      jest.advanceTimersByTime(23 * hr);
      await expect(get(baseURL, '/session', { cookieJar })).resolves.not.toThrow();
    }
    jest.advanceTimersByTime(25 * hr);
    await expect(get(baseURL, '/session', { cookieJar })).rejects.toThrowError('Unauthorized');
    clock.restoreAllMocks();
    jest.useRealTimers();
  });

  it('should not logout v1 users', async () => {
    // Cookie generated with v1 cookie store tests with v long absolute exp
    const V1_COOKIE =
      'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidWF0IjoxNjYyNDY2OTc2LCJpYXQiOjE2NjI0NjY5NzYsImV4cCI6NDgxODIyNjk3Nn0..3H_btn3Vk4SQhA0v.1tA8Olxj_1QTXRJYgY3FUtq1it-PunBKn2YKiO5cMCyf4ARF6sry4jfkq36aavaUYTh6w9mvAQawhcduOTzWOWtSbvRMOIlrOZTzUNohuLakKZA6ME2EgdLx1sMhuhtRdA1qACSDqly4qPw9IcOo1IUsYRzhtyI8MaYncjLzRHpo1Lvq_F5vtg5PIDTkYVnrhRX-SPsx6jbCr0rXxU3Cp9X8YYt-tl5yW-TLBPAeBy0TR-iiYJWMNyTMPE00o2LqsC2NQN7AySNtaaURb_a0cSpkF2X1fAb_iAKw-bg1wTruKUulErXkwTKPzZW6L0sGtnWN4qTg8gfxnoZxxrf7s-x2xCzKefiR0_8qpdfo0zhtE-PTYCFZxTU46yIkGZbJgVaH-tavoe1G3YhKMLEau49KV29agjVlN6eB5beEK2H70BgbaSPM4rcOhfqVeB5dku9olKCppI4UAtahaQqwnQrf1vd0W-qbslN_KO84QaBf8YlzGDbnfOAgXobqNnMu_-BoEInODK4azk_d9BquukhEm0g47XNYZuVCmgqNLo3Nul15lmHzZPGQ2ITivG7Dfb7sCLrKM6omioUjVCs6K6TCp100ndxQZuKUXYF2JkQoJhEge6MBSZDMF0cwIZlg1w8ArbPKl16zdZl8MYqDR_Vtwx7feT8sOvqST5he7oXp0yH2SvcG0dQbJLgPrmOOfDZIbjae11mcoIKa5oVVf4O_h-yHSVYyky8zLX-r7QP_H8CwMi19SysQa7S0b5BDlc5fn4ndf75TR7Zgg7r8PxzQiQghYoJXMZgzDpsaq8i33z2KMrwiGZPiDTuLmeOoV2BKNAVpBpad86BN_d2K7wAmPGx5ysWTc4mxSTv0b1E4G5_ZGDF59wl1m4o1zCSgMqZ56VCqb5qksPPhjpWjnbLnLw_6R_i4aqAxwHkdHOzbbSAGfwpBQF8PRDlmkIlZRQ9QRoLuWVdc3lJfX_Xp_ZKY9j8rKtOOC8BGq2yAZDIv0ezJPwLYEgi8_zdfufyogTLPOs0tIcImJIMasba5MqpHzOcKCsjnptUt2OF83Vyinw.NLZleTxnLwai5TN2wvcXhg';
    const baseURL = await setup({
      ...defaultConfig,
      session: { rolling: false, absoluteDuration: day * 365 * 100 }
    });
    const appSession = V1_COOKIE;
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
});
