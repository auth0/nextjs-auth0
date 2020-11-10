import { randomBytes } from 'crypto';
import { JWK, JWE } from 'jose';
import { IdTokenClaims } from 'openid-client';
import { setup, teardown } from './fixture/server';
import { defaultConfig, fromCookieJar, get, toCookieJar } from './fixture/helpers';
import { encryption as deriveKey } from '../../src/auth0-session/utils/hkdf';
import { makeIdToken } from './fixture/cert';

const key = JWK.asKey(deriveKey(defaultConfig.secret));

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
// const { cleartext: decrypted } = JWE.decrypt(encrypted, key, {
//   complete: true,
//   contentEncryptionAlgorithms: [encryptOpts.enc],
//   keyManagementAlgorithms: [encryptOpts.alg]
// });

describe('CookieStore', () => {
  afterEach(teardown);

  it('should not create a session when there are no cookies', async () => {
    await setup(defaultConfig);
    await expect(get('/session')).rejects.toThrowError('Unauthorized');
  });

  it('should not throw for malformed sessions', async () => {
    await setup(defaultConfig);
    const cookieJar = toCookieJar({
      appSession: '__invalid_identity__'
    });
    await expect(get('/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should not error with JWEDecryptionFailed when using old secrets', async () => {
    await setup({ ...defaultConfig, secret: '__invalid_secret__' });
    const cookieJar = toCookieJar({ appSession: encrypted() });
    await expect(get('/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should get an existing session', async () => {
    await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession });
    const session = await get('/session', { cookieJar });
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
    await setup(defaultConfig);
    const appSession = encrypted({
      big_claim: randomBytes(4000).toString('base64')
    });
    const cookieJar = toCookieJar({ appSession });
    await get('/session', { cookieJar });
    const cookies = fromCookieJar(cookieJar);
    expect(cookies).toHaveProperty('appSession.0');
    expect(cookies).toHaveProperty('appSession.1');
    const session = await get('/session', { cookieJar });
    expect(session.claims).toHaveProperty('big_claim');
  });

  it('should handle unordered chunked cookies', async () => {
    await setup(defaultConfig);
    const appSession = encrypted({ sub: '__chunked_sub__' });
    const cookieJar = toCookieJar({
      'appSession.2': appSession.slice(20),
      'appSession.0': appSession.slice(0, 10),
      'appSession.1': appSession.slice(10, 20)
    });
    const session = await get('/session', { cookieJar });
    expect(session.claims.sub).toEqual('__chunked_sub__');
  });

  it('should not throw for malformed cookie chunks', async () => {
    await setup(defaultConfig);
    const cookieJar = toCookieJar({
      'appSession.2': 'foo',
      'appSession.0': 'bar'
    });
    await expect(get('/session', { cookieJar })).rejects.toThrowError('Unauthorized');
  });

  it('should set the default cookie options on http', async () => {
    await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession });
    await get('/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(defaultConfig.baseURL);
    expect(cookie).toMatchObject({
      domain: 'localhost',
      httpOnly: true,
      key: 'appSession',
      maxAge: expect.any(Number),
      path: '/',
      sameSite: 'lax'
    });
  });

  it('should set the default cookie options on http', async () => {
    await setup(defaultConfig);
    const appSession = encrypted();
    const cookieJar = toCookieJar({ appSession });
    await get('/session', { cookieJar });
    const [cookie] = cookieJar.getCookiesSync(defaultConfig.baseURL);
    expect(cookie).toMatchObject({
      domain: 'localhost',
      httpOnly: true,
      key: 'appSession',
      maxAge: expect.any(Number),
      path: '/',
      sameSite: 'lax'
    });
  });
  //
  // it('should set the custom cookie options', async () => {
  //   server = await createServer(
  //     appSession(
  //       getConfig({
  //         ...defaultConfig,
  //         session: {
  //           cookie: {
  //             httpOnly: false,
  //             sameSite: 'Strict'
  //           }
  //         }
  //       })
  //     )
  //   );
  //   const jar = request.jar();
  //   await request.get('/session', {
  //     baseUrl,
  //     json: true,
  //     jar,
  //     headers: {
  //       cookie: `appSession=${encrypted}`
  //     }
  //   });
  //   const [cookie] = jar.getCookies(baseUrl);
  //   assert.deepInclude(cookie, {
  //     key: 'appSession',
  //     httpOnly: false,
  //     extensions: ['SameSite=Strict']
  //   });
  // });
  //
  // it('should use a custom cookie name', async () => {
  //   server = await createServer(
  //     appSession(
  //       getConfig({
  //         ...defaultConfig,
  //         session: { name: 'customName' }
  //       })
  //     )
  //   );
  //   const jar = request.jar();
  //   const res = await request.get('/session', {
  //     baseUrl,
  //     json: true,
  //     jar,
  //     headers: {
  //       cookie: `customName=${encrypted}`
  //     }
  //   });
  //   const [cookie] = jar.getCookies(baseUrl);
  //   assert.equal(res.statusCode, 200);
  //   assert.equal(cookie.key, 'customName');
  // });
  //
  // it('should set an ephemeral cookie', async () => {
  //   server = await createServer(
  //     appSession(
  //       getConfig({
  //         ...defaultConfig,
  //         session: { cookie: { transient: true } }
  //       })
  //     )
  //   );
  //   const jar = request.jar();
  //   const res = await request.get('/session', {
  //     baseUrl,
  //     json: true,
  //     jar,
  //     headers: {
  //       cookie: `appSession=${encrypted}`
  //     }
  //   });
  //   const [cookie] = jar.getCookies(baseUrl);
  //   assert.equal(res.statusCode, 200);
  //   assert.isFalse(cookie.hasOwnProperty('expires'));
  // });
  //
  // it('should not throw for expired cookies', async () => {
  //   const twoWeeks = 2 * 7 * 24 * 60 * 60 * 1000;
  //   const clock = sinon.useFakeTimers({
  //     now: Date.now(),
  //     toFake: ['Date']
  //   });
  //   server = await createServer(appSession(getConfig(defaultConfig)));
  //   const jar = request.jar();
  //   clock.tick(twoWeeks);
  //   const res = await request.get('/session', {
  //     baseUrl,
  //     json: true,
  //     jar,
  //     headers: {
  //       cookie: `appSession=${encrypted}`
  //     }
  //   });
  //   assert.equal(res.statusCode, 200);
  //   clock.restore();
  // });
  //
  // it('should throw for duplicate mw', async () => {
  //   server = await createServer((req, res, next) => {
  //     req.appSession = {};
  //     appSession(getConfig(defaultConfig))(req, res, next);
  //   });
  //   const res = await request.get('/session', { baseUrl, json: true });
  //   assert.equal(res.statusCode, 500);
  //   assert.equal(res.body.err.message, 'req[appSession] is already set, did you run this middleware twice?');
  // });
  //
  // it('should throw for reassigning session', async () => {
  //   server = await createServer((req, res, next) => {
  //     appSession(getConfig(defaultConfig))(req, res, () => {
  //       req.appSession = {};
  //       next();
  //     });
  //   });
  //   const res = await request.get('/session', { baseUrl, json: true });
  //   assert.equal(res.statusCode, 500);
  //   assert.equal(res.body.err.message, 'session object cannot be reassigned');
  // });
  //
  // it('should not throw for reassigining session to empty', async () => {
  //   server = await createServer((req, res, next) => {
  //     appSession(getConfig(defaultConfig))(req, res, () => {
  //       req.appSession = null;
  //       req.appSession = undefined;
  //       next();
  //     });
  //   });
  //   const res = await request.get('/session', { baseUrl, json: true });
  //   assert.equal(res.statusCode, 200);
  // });
  //
  // it('should expire after 24hrs of inactivity by default', async () => {
  //   const clock = sinon.useFakeTimers({ toFake: ['Date'] });
  //   server = await createServer(appSession(getConfig(defaultConfig)));
  //   const jar = await login({ sub: '__test_sub__' });
  //   let res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isNotEmpty(res.body);
  //   clock.tick(23 * HR_MS);
  //   res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isNotEmpty(res.body);
  //   clock.tick(25 * HR_MS);
  //   res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isEmpty(res.body);
  //   clock.restore();
  // });
  //
  // it('should expire after 7days regardless of activity by default', async () => {
  //   const clock = sinon.useFakeTimers({ toFake: ['Date'] });
  //   server = await createServer(appSession(getConfig(defaultConfig)));
  //   const jar = await login({ sub: '__test_sub__' });
  //   let days = 7;
  //   while (days--) {
  //     clock.tick(23 * HR_MS);
  //     let res = await request.get('/session', { baseUrl, jar, json: true });
  //     assert.isNotEmpty(res.body);
  //   }
  //   clock.tick(8 * HR_MS);
  //   let res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isEmpty(res.body);
  //   clock.restore();
  // });
  //
  // it('should expire only after defined absoluteDuration', async () => {
  //   const clock = sinon.useFakeTimers({ toFake: ['Date'] });
  //   server = await createServer(
  //     appSession(
  //       getConfig({
  //         ...defaultConfig,
  //         session: {
  //           rolling: false,
  //           absoluteDuration: 10 * 60 * 60
  //         }
  //       })
  //     )
  //   );
  //   const jar = await login({ sub: '__test_sub__' });
  //   clock.tick(9 * HR_MS);
  //   let res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isNotEmpty(res.body);
  //   clock.tick(2 * HR_MS);
  //   res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isEmpty(res.body);
  //   clock.restore();
  // });
  //
  // it('should expire only after defined rollingDuration period of inactivty', async () => {
  //   const clock = sinon.useFakeTimers({ toFake: ['Date'] });
  //   server = await createServer(
  //     appSession(
  //       getConfig({
  //         ...defaultConfig,
  //         session: {
  //           rolling: true,
  //           rollingDuration: 24 * 60 * 60,
  //           absoluteDuration: false
  //         }
  //       })
  //     )
  //   );
  //   const jar = await login({ sub: '__test_sub__' });
  //   let days = 30;
  //   while (days--) {
  //     clock.tick(23 * HR_MS);
  //     let res = await request.get('/session', { baseUrl, jar, json: true });
  //     assert.isNotEmpty(res.body);
  //   }
  //   clock.tick(25 * HR_MS);
  //   let res = await request.get('/session', { baseUrl, jar, json: true });
  //   assert.isEmpty(res.body);
  //   clock.restore();
  // });
});
