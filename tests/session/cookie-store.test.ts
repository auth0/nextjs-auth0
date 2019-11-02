import { parse } from 'cookie';
import jose from '@panva/jose';
import getRequestResponse from '../helpers/http';
import timekeeper from 'timekeeper';
import CookieStore from '../../src/session/cookie-store';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';
import { withoutApi } from '../helpers/default-settings';
import getClient from '../../src/utils/oidc-client';
import { discovery, jwksEndpoint, refreshToken } from '../helpers/oidc-nocks';

describe('cookie store', () => {
  let keystore: jose.JWKS.KeyStore;

  beforeAll(() => {
    keystore = new jose.JWKS.KeyStore();
    return keystore.generate('RSA');
  });

  const getStore = (settings = {}): CookieStore => {
    const store = new CookieStore(
      new CookieSessionStoreSettings({
        cookieSecret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat',
        ...settings
      }),
      getClient(withoutApi)
    );
    return store;
  };

  describe('with cookie name', () => {
    describe('configured', () => {
      const store = getStore({
        cookieName: 'my-cookie'
      });

      test('should set the cookie name', async () => {
        const { req, res } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        expect(res.setHeader).toHaveBeenCalledWith('Set-Cookie', expect.stringMatching('my-cookie='));
      });
    });

    describe('not configured', () => {
      const store = getStore({});

      test('should use default settings', async () => {
        const { req, res } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        expect(res.setHeader).toHaveBeenCalledWith('Set-Cookie', expect.stringMatching('a0:session='));
      });
    });
  });

  describe('with storeAccessToken', () => {
    describe('configured', () => {
      const store = getStore({});

      test('should not store the access_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token'
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          user: { sub: '123' },
          createdAt: now
        });
      });
    });

    describe('not configured', () => {
      const store = getStore({
        storeAccessToken: true
      });

      test('should store the access_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token'
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token'
        });
      });
    });
  });

  describe('with storeIdToken', () => {
    describe('not configured', () => {
      const store = getStore({});

      test('should not store the id_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token'
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          createdAt: now,
          user: { sub: '123' }
        });
      });
    });

    describe('configured', () => {
      const store = getStore({
        storeIdToken: true
      });

      test('should store the id_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token'
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          createdAt: now,
          idToken: 'my-id-token',
          user: { sub: '123' }
        });
      });
    });
  });

  describe('with storeRefreshToken', () => {
    describe('not configured', () => {
      const store = getStore({});

      test('should not store the refresh_token or expires_at', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token',
          expiresAt: Date.now()
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          createdAt: now,
          user: { sub: '123' }
        });
      });
    });

    describe('configured', () => {
      const store = getStore({
        storeRefreshToken: true,
        storeAccessToken: true
      });

      test('should store the refresh_token and expires_at', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token',
          expiresAt: now
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          createdAt: now,
          refreshToken: 'my-refresh-token',
          user: { sub: '123' },
          expiresAt: now
        });
      });

      test('should refresh the token when it expires', async () => {
        const time = new Date();
        timekeeper.freeze(time);

        discovery(withoutApi);
        jwksEndpoint(withoutApi, keystore.toJWKS());
        refreshToken(withoutApi, 'my-refresh-token', keystore.get(), {
          sub: '123'
        }, 'new-token');

        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token',
          accessToken: 'my-access-token',
          // expires_at is in seconds
          expiresAt: (now / 1000) - 1
        });

        const [, cookie] = setHeaderFn.mock.calls[0];
        req.headers = {
          ...req.headers,
          cookie: `a0:session=${parse(cookie)['a0:session']}`
        };

        const session = await store.read(req, res);
        expect(session).toEqual({
          createdAt: now,
          refreshToken: 'my-refresh-token',
          accessToken: 'new-token',
          user: { sub: '123' },
          expiresAt: now / 1000
        });

        timekeeper.reset();
      })
    });
  });
});
