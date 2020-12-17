import { withoutApi } from '../helpers/default-settings';
import { userInfo, discovery, jwksEndpoint, codeExchange } from '../helpers/oidc-nocks';
import { CallbackOptions, ConfigParameters } from '../../src/auth0-session';
import { initAuth0 } from '../../src';

import { start, stop } from '../helpers/server';
import { get, post, toSignedCookieJar } from '../auth0-session/fixture/helpers';
import { ProfileOptions } from '../../src/handlers';
import { CookieJar } from 'tough-cookie';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { jwks, makeIdToken } from '../auth0-session/fixture/cert';
import { TokenSet } from 'openid-client';
import nock = require('nock');

const login = async (baseUrl: string): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: '/' });
  const cookieJar = toSignedCookieJar({ state, nonce }, baseUrl);
  await post(baseUrl, '/api/auth/callback', {
    fullResponse: true,
    body: {
      state,
      code: 'code'
    },
    cookieJar
  });
  return cookieJar;
};

const setupHandler = async (
  config: ConfigParameters,
  userInfoPayload: any = {},
  profileOptions?: ProfileOptions,
  callbackOptions?: CallbackOptions,
  discoveryOptions?: any
): Promise<string> => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  userInfo(config, 'eyJz93a...k4laUWw', userInfoPayload);
  codeExchange(config, makeIdToken({ iss: 'https://acme.auth0.local/' }));
  const { handleAuth, handleProfile, getSession, handleCallback } = await initAuth0(config);
  (global as any).handleAuth = handleAuth.bind(null, {
    async profile(req, res) {
      try {
        await handleProfile(req, res, profileOptions);
      } catch (error) {
        res.statusMessage = error.message;
        res.status(error.status || 500).end(error.message);
      }
    },
    async callback(req, res) {
      try {
        await handleCallback(req, res, callbackOptions);
      } catch (error) {
        res.statusMessage = error.message;
        res.status(error.status || 500).end(error.message);
      }
    }
  });
  (global as any).getSession = getSession;
  return start();
};

describe('profile handler', () => {
  afterEach(async () => {
    jest.resetModules();
    nock.cleanAll();
    await stop();
  });

  test('should throw an error when not logged in', async () => {
    const baseUrl = await setupHandler(withoutApi);

    await expect(get(baseUrl, '/api/auth/me')).rejects.toThrow('Unauthorized');
  });

  test('should return the profile when logged in', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toStrictEqual({ nickname: '__test_nickname__', sub: '__test_sub__' });
  });

  test('should throw if refetching with no Access Token', async () => {
    const afterCallback = (_req: any, _res: any, tokenSet: TokenSet): TokenSet => {
      delete tokenSet.access_token;
      return tokenSet;
    };
    const baseUrl = await setupHandler(withoutApi, {}, { refetch: true }, { afterCallback });
    const cookieJar = await login(baseUrl);

    await expect(get(baseUrl, '/api/auth/me', { cookieJar })).rejects.toThrow(
      'The user does not have a valid access token.'
    );
  });

  test('should refetch the user and update the session', async () => {
    const baseUrl = await setupHandler(withoutApi, { foo: 'bar' }, { refetch: true });
    const cookieJar = await login(baseUrl);

    const profile = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
    // check that the session is saved
    userInfo(withoutApi, 'eyJz93a...k4laUWw', {});
    const profile2 = await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(profile2).toMatchObject({ foo: 'bar', nickname: '__test_nickname__', sub: '__test_sub__' });
  });
});
