import { start, stop } from '../helpers/server';
import { ConfigParameters } from '../../src/auth0-session';
import { withApi, withoutApi } from '../helpers/default-settings';
import { codeExchange, discovery, jwksEndpoint } from '../helpers/oidc-nocks';
import { jwks, makeIdToken /*, makeIdToken*/ } from '../auth0-session/fixture/cert';
import { initAuth0 } from '../../src';
import { get, post, toSignedCookieJar } from '../auth0-session/fixture/helpers';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { CookieJar } from 'tough-cookie';
import timekeeper = require('timekeeper');
import { CallbackOptions } from '../../src/auth0-session';
import { TokenSet } from 'openid-client';
import nock = require('nock');

const setupHandler = async (
  config: ConfigParameters,
  idTokenClaims: any = {},
  callbackOptions?: CallbackOptions,
  discoveryOptions?: any
): Promise<string> => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  codeExchange(config, makeIdToken(idTokenClaims));
  const { handleAuth, handleCallback, getSession } = await initAuth0(config);
  (global as any).handleAuth = handleAuth.bind(null, {
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

const callback = (baseUrl: string, body: any, cookieJar?: CookieJar): Promise<any> =>
  post(baseUrl, `/api/auth/callback`, {
    body,
    cookieJar,
    fullResponse: true
  });

describe('callback handler', () => {
  afterEach(async () => {
    jest.resetModules();
    nock.cleanAll();
    await stop();
  });

  test('should require a state', async () => {
    const baseUrl = await setupHandler(withoutApi);
    await expect(
      callback(baseUrl, {
        state: '__test_state__'
      })
    ).rejects.toThrow('checks.state argument is missing');
  });

  test('should validate the state', async () => {
    const baseUrl = await setupHandler(withoutApi);
    const cookieJar = toSignedCookieJar(
      {
        state: '__other_state__'
      },
      baseUrl
    );
    await expect(
      callback(
        baseUrl,
        {
          state: '__test_state__'
        },
        cookieJar
      )
    ).rejects.toThrow('state mismatch, expected __other_state__, got: __test_state__');
  });

  test('should validate the audience', async () => {
    const baseUrl = await setupHandler(withoutApi, { aud: 'bar', iss: 'https://acme.auth0.local/' });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    await expect(
      callback(
        baseUrl,
        {
          state,
          code: 'code'
        },
        cookieJar
      )
    ).rejects.toThrow('aud mismatch, expected __test_client_id__, got: bar');
  });

  test('should validate the issuer', async () => {
    const baseUrl = await setupHandler(withoutApi, { aud: 'bar', iss: 'other-issuer' });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    await expect(
      callback(
        baseUrl,
        {
          state,
          code: 'code'
        },
        cookieJar
      )
    ).rejects.toThrow('unexpected iss value, expected https://acme.auth0.local/, got: other-issuer');
  });

  test('should allow id_tokens to be set in the future', async () => {
    // TODO: see if you can make this fail on master
    const baseUrl = await setupHandler(withoutApi, {
      iss: 'https://acme.auth0.local/',
      iat: Math.floor(new Date(new Date().getTime() + 10 * 1000).getTime() / 1000)
    });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await callback(
      baseUrl,
      {
        state,
        code: 'code'
      },
      cookieJar
    );
    expect(res.statusCode).toBe(302);
  });

  test('should create the session without OIDC claims', async () => {
    const baseUrl = await setupHandler(withoutApi, { iss: 'https://acme.auth0.local/' });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await callback(
      baseUrl,
      {
        state,
        code: 'code'
      },
      cookieJar
    );
    expect(res.statusCode).toBe(302);
    const body = await get(baseUrl, `/api/session`, { cookieJar });

    expect(body.user).toStrictEqual({
      nickname: '__test_nickname__',
      sub: '__test_sub__'
    });
  });

  test('should set the correct expiration', async () => {
    timekeeper.freeze(0);
    const baseUrl = await setupHandler(withoutApi, { iss: 'https://acme.auth0.local/' });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await post(baseUrl, `/api/auth/callback`, {
      fullResponse: true,
      cookieJar,
      body: {
        state,
        code: 'code'
      }
    });
    expect(res.statusCode).toBe(302);

    const [sessionCookie] = cookieJar.getCookiesSync(baseUrl);
    const expiryInHrs = new Date(sessionCookie.expires).getTime() / 1000 / 60 / 60;
    expect(expiryInHrs).toBe(24);
    timekeeper.reset();
  });

  test('should create the session without OIDC claims with api config', async () => {
    timekeeper.freeze(0);
    const baseUrl = await setupHandler(withApi, { iss: 'https://acme.auth0.local/' });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await callback(
      baseUrl,
      {
        state,
        code: 'code'
      },
      cookieJar
    );
    expect(res.statusCode).toBe(302);
    const session = await get(baseUrl, `/api/session`, { cookieJar });

    expect(session).toStrictEqual({
      accessToken: 'eyJz93a...k4laUWw',
      accessTokenExpiresAt: 750,
      accessTokenScope: 'read:foo delete:foo',
      idToken: makeIdToken({ iss: 'https://acme.auth0.local/' }),
      token_type: 'Bearer',
      refreshToken: 'GEbRxBN...edjnXbL',
      user: {
        nickname: '__test_nickname__',
        sub: '__test_sub__'
      }
    });
    timekeeper.reset();
  });

  test('remove tokens with afterCallback hook', async () => {
    timekeeper.freeze(0);
    const afterCallback = (_req: any, _res: any, tokenSet: TokenSet): TokenSet => {
      delete tokenSet.access_token;
      delete tokenSet.refresh_token;
      return tokenSet;
    };
    const baseUrl = await setupHandler(withApi, { iss: 'https://acme.auth0.local/' }, { afterCallback });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await callback(
      baseUrl,
      {
        state,
        code: 'code'
      },
      cookieJar
    );
    expect(res.statusCode).toBe(302);
    const session = await get(baseUrl, `/api/session`, { cookieJar });

    expect(session).toStrictEqual({
      accessTokenExpiresAt: 750,
      accessTokenScope: 'read:foo delete:foo',
      idToken: makeIdToken({ iss: 'https://acme.auth0.local/' }),
      token_type: 'Bearer',
      user: {
        nickname: '__test_nickname__',
        sub: '__test_sub__'
      }
    });
    timekeeper.reset();
  });

  test('add properties to session with afterCallback hook', async () => {
    timekeeper.freeze(0);
    const afterCallback = (_req: any, _res: any, tokenSet: TokenSet): TokenSet => {
      tokenSet.foo = 'bar';
      return tokenSet;
    };
    const baseUrl = await setupHandler(withApi, { iss: 'https://acme.auth0.local/' }, { afterCallback });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    const { res } = await callback(
      baseUrl,
      {
        state,
        code: 'code'
      },
      cookieJar
    );
    expect(res.statusCode).toBe(302);
    const session = await get(baseUrl, '/api/session', { cookieJar });

    expect(session).toMatchObject({
      foo: 'bar',
      user: {
        nickname: '__test_nickname__',
        sub: '__test_sub__'
      }
    });
    timekeeper.reset();
  });

  test('throws from afterCallback hook', async () => {
    const afterCallback = (): TokenSet => {
      throw new Error('some validation error.');
    };
    const baseUrl = await setupHandler(withApi, { iss: 'https://acme.auth0.local/' }, { afterCallback });
    const state = encodeState({ returnTo: baseUrl });
    const cookieJar = toSignedCookieJar(
      {
        state,
        nonce: '__test_nonce__'
      },
      baseUrl
    );
    await expect(
      callback(
        baseUrl,
        {
          state,
          code: 'code'
        },
        cookieJar
      )
    ).rejects.toThrow('some validation error.');
  });
});
