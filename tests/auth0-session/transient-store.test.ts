import { IncomingMessage, ServerResponse } from 'http';
import { JWK, JWS } from 'jose';
import { CookieJar } from 'tough-cookie';
import { getConfig, TransientStore } from '../../src/auth0-session';
import { signing as deriveKey } from '../../src/auth0-session/utils/hkdf';
import { defaultConfig, fromCookieJar, get, getCookie, toSignedCookieJar } from './fixtures/helpers';
import { setup as createServer, teardown } from './fixtures/server';

const generateSignature = (cookie: string, value: string): string => {
  const key = JWK.asKey(deriveKey(defaultConfig.secret as string));
  return JWS.sign.flattened(Buffer.from(`${cookie}=${value}`), key, {
    alg: 'HS256',
    b64: false,
    crit: ['b64']
  }).signature;
};

const setup = async (params = defaultConfig, cb: Function, https = true): Promise<string> =>
  createServer(params, {
    customListener: (req, res) => {
      res.end(JSON.stringify({ value: cb(req, res) }));
    },
    https
  });

describe('TransientStore', () => {
  afterEach(teardown);

  it('should use the passed-in key to set the cookies', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(value).toEqual(cookies['test_key']);
    expect(value).toEqual(cookies['_test_key']);
  });

  it('should accept list of secrets', async () => {
    const baseURL = await setup(
      { ...defaultConfig, secret: ['__old_secret__', defaultConfig.secret as string] },
      (req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(value).toEqual(cookies['test_key']);
    expect(value).toEqual(cookies['_test_key']);
  });

  it('should set cookie to secure by default when baseURL protocol is https', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookie = getCookie('test_key', cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(cookie?.secure).toEqual(true);
  });

  it('should override the secure setting when specified', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { sameSite: 'lax', value: 'foo' })
    );
    const transientStore = new TransientStore(
      getConfig({ ...defaultConfig, baseURL, session: { cookie: { secure: false } } })
    );
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookie = getCookie('test_key', cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(cookie?.secure).toEqual(false);
  });

  it('should set cookie to not secure when baseURL protocol is http and SameSite=Lax', async () => {
    const baseURL = await setup(
      defaultConfig,
      (req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res, { value: 'foo' }),
      false
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookie = getCookie('test_key', cookieJar, baseURL);
    expect(value).toEqual(expect.any(String));
    expect(cookie?.secure).toBeFalsy();
  });

  it('should set SameSite=None, Secure=False for fallback cookie by default for http', async () => {
    const baseURL = await setup(
      defaultConfig,
      (req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res, { value: 'foo' }),
      false
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const fallbackCookie = getCookie('_test_key', cookieJar, baseURL);
    expect(value).toEqual(expect.any(String));
    expect(fallbackCookie).toMatchObject({
      sameSite: 'none',
      secure: false,
      httpOnly: true
    });
  });

  it('should turn off fallback', async () => {
    const baseURL = await setup(
      { ...defaultConfig, legacySameSiteCookie: false },
      (req: IncomingMessage, res: ServerResponse) => transientStore.save('test_key', req, res, { value: 'foo' })
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL, legacySameSiteCookie: false }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should set custom SameSite with no fallback', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.save('test_key', req, res, { sameSite: 'lax', value: 'foo' })
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = new CookieJar();
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    const cookie = getCookie('test_key', cookieJar, baseURL);
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
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.read('test_key', req, res)
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const { value } = await get(baseURL, '/');
    expect(value).toBeUndefined();
  });

  it('should return main value and delete both cookies by default', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.read('test_key', req, res)
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = toSignedCookieJar(
      {
        test_key: `foo.${generateSignature('test_key', 'foo')}`,
        _test_key: `foo.${generateSignature('_test_key', 'foo')}`
      },
      baseURL
    );

    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('test_key');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should return fallback value and delete both cookies if main value not present', async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.read('test_key', req, res)
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = toSignedCookieJar(
      {
        _test_key: `foo.${generateSignature('_test_key', 'foo')}`
      },
      baseURL
    );
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toEqual('foo');
    expect(cookies).not.toHaveProperty('test_key');
    expect(cookies).not.toHaveProperty('_test_key');
  });

  it('should not check fallback value when legacySameSiteCookie is false', async () => {
    const baseURL = await setup(
      { ...defaultConfig, legacySameSiteCookie: false },
      (req: IncomingMessage, res: ServerResponse) => transientStore.read('test_key', req, res)
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL, legacySameSiteCookie: false }));
    const cookieJar = toSignedCookieJar(
      {
        _test_key: `foo.${generateSignature('_test_key', 'foo')}`
      },
      baseURL
    );
    const { value } = await get(baseURL, '/', { cookieJar });
    const cookies = fromCookieJar(cookieJar, baseURL);
    expect(value).toBeUndefined();
    expect(cookies).toHaveProperty('_test_key');
  });

  it("should not throw when it can't verify the signature", async () => {
    const baseURL = await setup(defaultConfig, (req: IncomingMessage, res: ServerResponse) =>
      transientStore.read('test_key', req, res)
    );
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL }));
    const cookieJar = toSignedCookieJar(
      {
        test_key: 'foo.bar',
        _test_key: 'foo.bar'
      },
      baseURL
    );

    const { value } = await get(baseURL, '/', { cookieJar });
    expect(value).toBeUndefined();
  });

  it('should generate a code verifier and challenge', async () => {
    const transientStore = new TransientStore(getConfig({ ...defaultConfig, baseURL: 'http://example.com' }));
    expect(transientStore.generateCodeVerifier()).toEqual(expect.any(String));
    expect(transientStore.calculateCodeChallenge('foo')).toEqual(expect.any(String));
  });
});
