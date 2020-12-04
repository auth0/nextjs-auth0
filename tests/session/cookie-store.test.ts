import { parse } from 'cookie';

import getRequestResponse from '../helpers/http';
import CookieStore from '../../src/session/cookie-store';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';

describe('CookieStore', () => {
  const getStore = (settings = {}): CookieStore => {
    const store = new CookieStore(
      new CookieSessionStoreSettings({
        cookieSecret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat',
        ...settings
      })
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

        expect(res.setHeader).toHaveBeenCalledWith(
          'Set-Cookie',
          expect.arrayContaining([expect.stringMatching('my-cookie.0=')])
        );
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

        expect(res.setHeader).toHaveBeenCalledWith(
          'Set-Cookie',
          expect.arrayContaining([expect.stringMatching('a0:session.0=')])
        );
      });
    });
  });

  describe('with cookie domain', () => {
    describe('configured', () => {
      const store = getStore({
        cookieDomain: '.quirk.fyi'
      });

      test('should set cookie domain', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        const [, [cookie]] = setHeaderFn.mock.calls[0];
        expect(parse(cookie).Domain).toBe('.quirk.fyi');
      });
    });

    describe('not configured', () => {
      const store = getStore({});

      test('should not set the cookie domain', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        const [, [cookie]] = setHeaderFn.mock.calls[0];
        expect(parse(cookie).Domain).toBeUndefined();
      });
    });
  });

  describe('with SameSite', () => {
    describe('configured', () => {
      const store = getStore({
        cookieSameSite: 'strict'
      });

      test('should set the SameSite setting correctly', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        const [, [cookie]] = setHeaderFn.mock.calls[0];
        expect(parse(cookie).SameSite).toBe('Strict');
      });
    });

    describe('not configured', () => {
      const store = getStore({});

      test('should default to Lax', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        const [, [cookie]] = setHeaderFn.mock.calls[0];
        expect(parse(cookie).SameSite).toBe('Lax');
      });
    });

    describe('set to disabled', () => {
      const store = getStore({
        cookieSameSite: false
      });
      test('should not set the SameSite option', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: Date.now()
        });

        const [, [cookie]] = setHeaderFn.mock.calls[0];
        expect(parse(cookie).SameSite).toBeUndefined();
      });
    });
  });

  describe('with very long content', () => {
    const longContent = '1234567890'.repeat(500);

    test('should create small cookies', async () => {
      const store = getStore();
      const { req, res, setHeaderFn } = getRequestResponse();
      await store.save(req, res, {
        user: { sub: '123', payload: longContent },
        createdAt: Date.now()
      });

      const [, cookieHeaders] = setHeaderFn.mock.calls[0];
      expect(cookieHeaders.length).toBeGreaterThan(1);

      const cookies = parse(cookieHeaders.join('; '));
      expect(parseInt(cookies['a0:session.c'], 10)).toBeGreaterThan(1);

      for (let i = 0; i < parseInt(cookies['a0:session.c'], 10); i += 1) {
        expect(cookies[`a0:session.${i}`].length).toBeGreaterThan(0);
        expect(cookies[`a0:session.${i}`].length).toBeLessThanOrEqual(4000);
      }
    });

    test('should be able to read split cookies', async () => {
      const store = getStore();
      const { req, res, setHeaderFn } = getRequestResponse();

      const input = {
        user: { sub: '123', payload: longContent },
        createdAt: Date.now()
      };

      await store.save(req, res, input);

      const [, cookies] = setHeaderFn.mock.calls[0];

      req.headers = {
        cookie: cookies.join('; ')
      };

      const session = await store.read(req);
      expect(session).toEqual(input);
    });

    describe('when some of the cookies are lost', () => {
      const store = getStore();

      test('missing content cookies turn the session null', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const input = {
          user: { sub: '123', payload: longContent },
          createdAt: Date.now()
        };
        await store.save(req, res, input);
        const [, [content1, , count]] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: [content1, count].join('; ')
        };

        const session = await store.read(req);
        expect(session).toBeNull();
      });

      test('missing count cookie is survivable is content is short', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const input = {
          user: { sub: '123' },
          createdAt: Date.now()
        };
        await store.save(req, res, input);
        const [, [content1]] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: content1
        };

        const session = await store.read(req);
        expect(session).toEqual(input);
      });
    });
  });

  describe('with legacy cookies', () => {
    test('should be able to read them', async() => {
      const store = getStore({});
      const { req, res, setHeaderFn } = getRequestResponse();
      
      const now = Date.now();
      await store.save(req, res, {
        user: { sub: '123' },
        createdAt: now,
        accessToken: 'my-access-token',
        accessTokenScope: 'read:foo',
        accessTokenExpiresAt: 500
      });

      const [, cookies] = setHeaderFn.mock.calls[0];
      
      req.headers = {
        cookie: `a0:session=${cookies[0].substr(13)}` // legacy cookie store used a single cookie to store data
      }
      const session = await store.read(req);
      expect(session).toEqual({
        user: { sub: '123' },
        createdAt: now
      });
    });
  });

  describe('with storeAccessToken', () => {
    describe('not configured', () => {
      const store = getStore({});

      test('should not store the access_token fields', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token',
          accessTokenScope: 'read:foo',
          accessTokenExpiresAt: 500
        });

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
        expect(session).toEqual({
          user: { sub: '123' },
          createdAt: now
        });
      });
    });

    describe('configured', () => {
      const store = getStore({
        storeAccessToken: true
      });

      test('should store the access_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token',
          accessTokenScope: 'read:foo',
          accessTokenExpiresAt: 500
        });

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
        expect(session).toEqual({
          user: { sub: '123' },
          createdAt: now,
          accessToken: 'my-access-token',
          accessTokenScope: 'read:foo',
          accessTokenExpiresAt: 500
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

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
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

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
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

      test('should not store the refresh_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token'
        });

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
        expect(session).toEqual({
          createdAt: now,
          user: { sub: '123' }
        });
      });
    });

    describe('configured', () => {
      const store = getStore({
        storeRefreshToken: true
      });

      test('should store the refresh_token', async () => {
        const { req, res, setHeaderFn } = getRequestResponse();
        const now = Date.now();

        await store.save(req, res, {
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token'
        });

        const [, cookies] = setHeaderFn.mock.calls[0];
        req.headers = {
          ...req.headers,
          cookie: cookies.join('; ')
        };

        const session = await store.read(req);
        expect(session).toEqual({
          createdAt: now,
          refreshToken: 'my-refresh-token',
          user: { sub: '123' }
        });
      });
    });
  });
});
