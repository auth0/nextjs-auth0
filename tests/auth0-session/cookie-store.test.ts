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
      'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidWF0IjoxNjYxODU5MTU3LCJpYXQiOjE2NjE4NTkxNTcsImV4cCI6MTY2MjQ2Mzk1N30..OCJcC6r7EGwTznTi.fgWVT4r9Rt8XMxooHCJcNiF5KGv7H7pg9WVygDCKfDb8qlPQQjANlKmweAoSnOTMdVweM3qZ9fvHrttlIk-kPmi3I5puMydfqihqMKRsIo9vbx24OdtUW-ZtzSqfc_nfMtX7qiu4u39FncNL2DeByTZSUUyDLf8S8V-FMakhjhPnOkweF3ztDnWaEK6w8Y_WsBJgFjFdbu8ZgKupcfKCwfxRR9xgUD9rWZ4AIuLhDId-jelRku9CqoCgL17DPbO2ytj1xs45LHL2sQGEaFLQFPZJ6bfNKdPtXQX73_nL3lqj20PqnvmzNW6DDYW0T3-kQz_VCEnBd74dtmGFwoMVbJ64Agvj55Gn_5aKFxBbdP5vb1mdKVTD7HdMfNnAPMPPyXsyvGHHaOPjnnkU8W_sNCaARS37FLWNxP59vNSvpSlN_oWCxsekHmkXVfhihaasO692eL319CPXfVa0Y3pQxUny6TunWv-HwtiV4GyrNG0ACL5gjVNS6qpcSuzOKn8NY8Y0FMnf_ISw8mz3Zel0WI_AJqU3IsGWdTHkF97ss5ckCyV0Ij9ezycbispxQ269rReUPE6Se_m5TqY7Py64MXS8ZgdG_KPrAGRP4I1KP0nLKU8NdaloI2I1HiiiDIC5hMhnmXtAvweXgOumWSACBu6PvcdGFdA-ptYaaT3vKC2-XxeVc7ynxabEeogcaXN1H_4wZ2Tjk5eLVTRTRnl0p09HBULoMr2KZAkDRjP3P-m5_Cne-1v9xGx23zzpxi3FfAH2jDBBSwEfy-GXxr65-hmIng7dOko4ul8AqWmP1f2sSYrBB-R3EZjVV0V6ssxC5I1q6Q-Xw99QsunlOYsTfikmBOvfXqNvFF1YkzsgYms6-NSSMmZmMy1huhfqfLvKuGKttqAtDlVByGQU2zF8VArYNEFc2TidtkewyzbrgWK0ygntJ17QeLMYNadNgz7eTSRwe7x-Vho_tB3XFoYPYpyA2JwIS4pb1KEdQQDevSp-_sjMbWpHnD1hruvqbCC7Zo795_N1OXt-kBbXddVsoXqzKmKJEZIPGvcJMLgeI5rLrw.c1K7B6p_vbSH9ZZrF8Uqvg';
    const baseURL = await setup({ ...defaultConfig, session: { rolling: false } });
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
