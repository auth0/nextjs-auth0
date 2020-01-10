import jose from '@panva/jose';

import getRequestResponse from '../helpers/http';
import getClient from '../../src/utils/oidc-client';
import { withApi } from '../helpers/default-settings';

import { ISession } from '../../src/session/session';
import MemoryStore from '../../src/session/memory-store';
import { ITokenCache } from '../../src/tokens/token-cache';
import SessionTokenCache from '../../src/tokens/session-token-cache';
import { discovery, refreshTokenExchange, jwksEndpoint } from '../helpers/oidc-nocks';

describe('SessionTokenCache', () => {
  let keystore: jose.JWKS.KeyStore;

  function getTokenCache(
    options: { expiresIn?: number; scope?: string; accessToken?: string; refreshToken?: string } = {}
  ): { getSession: () => Promise<ISession | null>; cache: ITokenCache } {
    const client = getClient(withApi);
    const { req, res } = getRequestResponse();
    const session: ISession = {
      createdAt: Date.now(),
      accessToken: options.accessToken,
      accessTokenExpiresAt: options.expiresIn === undefined ? undefined : Date.now() / 1000 + options.expiresIn,
      accessTokenScope: options.scope,
      refreshToken: options.refreshToken,
      user: {
        sub: '456',
        name: 'user1'
      }
    };

    const store = new MemoryStore(session);
    return {
      getSession: (): Promise<ISession | null> => store.read(),
      cache: new SessionTokenCache(store, client, req, res)
    };
  }

  beforeAll(() => {
    keystore = new jose.JWKS.KeyStore();
    return keystore.generate('RSA');
  });

  describe('getAccessToken', () => {
    test('should fail if the session is missing', async () => {
      expect.assertions(1);

      const client = getClient(withApi);
      const { req, res } = getRequestResponse();
      const cache = new SessionTokenCache(new MemoryStore(), client, req, res);

      try {
        await cache.getAccessToken();
      } catch (e) {
        expect(e.code).toMatch('invalid_session');
      }
    });

    test('should fail if access_token and refresh_token are missing', async () => {
      expect.assertions(1);

      try {
        const { cache } = getTokenCache();
        await cache.getAccessToken();
      } catch (e) {
        expect(e.code).toMatch('invalid_session');
      }
    });

    test('should fail if the access token is expired', async () => {
      expect.assertions(1);

      try {
        const { cache } = getTokenCache({
          accessToken: 'foo',
          expiresIn: -60
        });
        await cache.getAccessToken();
      } catch (e) {
        expect(e.code).toMatch('access_token_expired');
      }
    });

    test('should fail if there is no access token', async () => {
      expect.assertions(1);

      try {
        const { cache } = getTokenCache({
          expiresIn: 65
        });
        await cache.getAccessToken();
      } catch (e) {
        expect(e.code).toMatch('invalid_session');
      }
    });

    test('should fail if the requested scopes cannot be satisfied', async () => {
      expect.assertions(1);

      const { cache } = getTokenCache({
        expiresIn: 65,
        accessToken: 'ey123',
        refreshToken: 'abc',
        scope: 'read:users read:documents'
      });

      try {
        await cache.getAccessToken({ scopes: ['read:documents', 'read:users', 'delete:files'] });
      } catch (e) {
        expect(e.code).toMatch('insufficient_scope');
      }
    });

    test('should return the access token', async () => {
      const { cache } = getTokenCache({
        expiresIn: 65,
        accessToken: 'ey123'
      });
      const result = await cache.getAccessToken();
      expect(result.accessToken).toMatch('ey123');
    });

    test('should fail if the requested scopes cannot be satisfied because no scopes are persisted', async () => {
      expect.assertions(1);

      try {
        const { cache } = getTokenCache({
          expiresIn: 65,
          accessToken: 'ey123',
          refreshToken: 'abc'
        });
        await cache.getAccessToken({ scopes: ['read:documents', 'read:users', 'delete:files'] });
      } catch (e) {
        expect(e.code).toMatch('insufficient_scope');
      }
    });

    describe('with refresh token', () => {
      test('should retrieve a new access token if the old one is expired and update the profile', async () => {
        expect.assertions(2);

        const { cache, getSession } = getTokenCache({
          expiresIn: -65,
          accessToken: 'ey123',
          refreshToken: 'abc'
        });

        discovery(withApi);
        jwksEndpoint(withApi, keystore.toJWKS());
        refreshTokenExchange(
          withApi,
          'abc',
          keystore.get(),
          {
            email: 'john@test.com',
            name: 'john doe',
            sub: '123'
          },
          'new-token'
        );

        const result = await cache.getAccessToken();
        expect(result.accessToken).toMatch('new-token');

        const session = await getSession();
        expect(session).toStrictEqual({
          accessToken: 'new-token',
          refreshToken: 'abc',
          idToken: expect.any(String),
          accessTokenExpiresAt: expect.any(Number),
          accessTokenScope: 'read:foo write:foo',
          createdAt: expect.any(Number),
          user: {
            email: 'john@test.com',
            name: 'john doe',
            sub: '123'
          }
        });
      });
    });
  });
});
