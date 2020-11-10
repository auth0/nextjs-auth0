import { IncomingMessage, ServerResponse, createServer as createHttpServer, Server as HttpServer } from 'http';
import { createServer as createHttpsServer, Server as HttpsServer } from 'https';
import { JWK, JWS } from 'jose';
import { CookieJar } from 'tough-cookie';
import { getConfig, TransientStore } from '../../src/auth0-session';
import { signing as deriveKey } from '../../src/auth0-session/utils/hkdf';
import {
  defaultConfig as baseDefaultConfig,
  fromCookieJar,
  get,
  getCookie,
  toSignedCookieJar
} from './fixture/helpers';
import { cert, key } from './fixture/https';

const baseUrl = 'https://localhost:3000';
const defaultConfig = { ...baseDefaultConfig, baseURL: baseUrl };

const generateSignature = (cookie: string, value: string): string => {
  const key = JWK.asKey(deriveKey(defaultConfig.secret));
  return JWS.sign.flattened(Buffer.from(`${cookie}=${value}`), key, {
    alg: 'HS256',
    b64: false,
    crit: ['b64']
  }).signature;
};

describe('TransientStore', () => {
  let server: HttpServer | HttpsServer;

  const setup = async (cb: Function, https = true): Promise<HttpsServer | HttpServer> => {
    server = (https ? createHttpsServer : createHttpServer)({ cert, key, rejectUnauthorized: false }, (req, res) => {
      res.end(JSON.stringify({ value: cb(req, res) }));
    });
    return new Promise((resolve) => server.listen(3000, () => resolve(server)));
  };

  const teardown = (): Promise<void> => new Promise((resolve) => server.close(resolve as (err?: Error) => void));

  afterEach(teardown);

  it('should use the passed-in key to set the cookies', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(value).toEqual(cookies['test_key']);
    expect(value).toEqual(cookies['_test_key']);
  });

  it('should accept list of secrets', async () => {
    const transientStore = new TransientStore(
      getConfig({ ...defaultConfig, secret: ['__old_secret__', defaultConfig.secret] })
    );
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(value).toEqual(cookies['test_key']);
    expect(value).toEqual(cookies['_test_key']);
  });

  it('should set cookie to secure by default when baseURL protocol is https', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookie = getCookie('test_key', cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(cookie?.secure).toEqual(true);
  });

  it('should override the secure setting when specified', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, session: { cookie: { secure: false } } }));
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { sameSite: 'lax', value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookie = getCookie('test_key', cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(cookie?.secure).toEqual(false);
  });

  it('should set cookie to not secure when baseURL protocol is http and SameSite=Lax', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL: 'http://localhost:3000' }));
    await setup(
      (req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res, { sameSite: 'lax' }),
      false
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar });
    const cookie = getCookie('test_key', cookieJar, 'http://localhost:3000');
    expect(value).toEqual(expect.any(String));
    expect(cookie?.secure).toBeFalsy();
  });

  it('should set SameSite=None, Secure=False for fallback cookie by default for http', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL: 'http://localhost:3000' }));
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res), false);
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar });
    const fallbackCookie = getCookie('_test_key', cookieJar, 'http://localhost:3000');
    expect(value).toEqual(expect.any(String));
    expect(fallbackCookie).toMatchObject({
      sameSite: 'none',
      secure: false,
      httpOnly: true
    });
  });

  it('should turn off fallback', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, legacySameSiteCookie: false }));
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should set custom SameSite with no fallback', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    await setup((req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { sameSite: 'lax', value: 'foo' })
    );
    const cookieJar = new CookieJar();
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar, baseUrl);
    const cookie = getCookie('test_key', cookieJar, baseUrl);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('_test_key');
    expect(cookie).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      value: expect.stringMatching(/^foo\..+/)
    });
  });

  it('should return undefined if there are no cookies', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res));
    const { value } = await get('/', { https: true });
    expect(value).toBeUndefined();
  });

  it('should return main value and delete both cookies by default', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    const cookieJar = toSignedCookieJar({
      test_key: `foo.${generateSignature('test_key', 'foo')}`,
      _test_key: `foo.${generateSignature('_test_key', 'foo')}`
    });
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res));
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('test_key');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should return fallback value and delete both cookies if main value not present', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    const cookieJar = toSignedCookieJar({
      _test_key: `foo.${generateSignature('_test_key', 'foo')}`
    });
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res));
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('test_key');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should not check fallback value when legacySameSiteCookie is false', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, legacySameSiteCookie: false }));
    const cookieJar = toSignedCookieJar({
      _test_key: `foo.${generateSignature('_test_key', 'foo')}`
    });
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res));
    const { value } = await get('/', { cookieJar, https: true });
    const cookies = fromCookieJar(cookieJar);
    expect(value).toBeUndefined();
    expect(cookies).toHaveProperty('_test_key');
  });

  it("should not throw when it can't verify the signature", async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    const cookieJar = toSignedCookieJar({
      test_key: 'foo.bar',
      _test_key: 'foo.bar'
    });
    await setup((req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res));
    const { value } = await get('/', { cookieJar, https: true });
    expect(value).toBeUndefined();
  });

  it('should generate a code verifier and challenge', async () => {
    const transientStore = new TransientStore(getConfig(defaultConfig));
    expect(transientStore.generateCodeVerifier()).toEqual(expect.any(String));
    expect(transientStore.calculateCodeChallenge('foo')).toEqual(expect.any(String));
  });
});
