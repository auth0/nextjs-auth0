import { promisify } from 'util';
import { CookieJar } from 'tough-cookie';
import getGot, { ToughCookieJar } from 'got';
import { JWK, JWT } from 'jose';
import { ConfigParameters } from '../../src/auth0-session';
import { setup, teardown } from './fixture/server';
import { generateCookieValue } from '../../src/auth0-session/transient-handler';
import { signing as deriveKey } from '../../src/auth0-session/utils/hkdf';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { makeIdToken } from './fixture/cert';

const clientId = '__test_client_id__';
const expectedDefaultState = encodeState({ returnTo: 'https://example.org' });
const baseUrl = 'http://localhost:3000';
const secret = '__test_session_secret__';
const defaultConfig: ConfigParameters = {
  secret,
  clientID: clientId,
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
  authRequired: false
};

const got = getGot.extend({
  prefixUrl: baseUrl
});

const cookies = async (cookies: { [key: string]: string }): Promise<ToughCookieJar> => {
  const cookieJar = new CookieJar();
  const setCookie = promisify(cookieJar.setCookie.bind(cookieJar));
  const jwk = JWK.asKey(deriveKey(secret));
  for (const [key, value] of Object.entries(cookies)) {
    await setCookie(`${key}=${generateCookieValue(key, value, jwk)}`, baseUrl);
  }
  return cookieJar as ToughCookieJar;
};

// For the purpose of this test the fake SERVER returns the error message in the body directly
// production application should have an error middleware.
// http://expressjs.com/en/guide/error-handling.html

describe('callback response_mode: form_post', () => {
  afterEach(() => {
    teardown();
  });

  it('should error when the body is empty', async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      nonce: '__test_nonce__',
      state: '__test_state__'
    });

    await expect(got.post('callback', { json: {}, cookieJar })).rejects.toThrowError(
      'Response code 400 (state missing from the response)'
    );
  });

  it('should error when the state cookie is missing', async () => {
    await setup(defaultConfig);

    await expect(
      got.post('callback', {
        json: {
          state: '__test_state__',
          id_token: '__invalid_token__'
        }
      })
    ).rejects.toThrowError('Response code 400 (checks.state argument is missing)');
  });

  it("should error when state doesn't match", async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      nonce: '__valid_nonce__',
      state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__invalid_state__',
          id_token: '__invalid_token__'
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (state mismatch, expected __valid_state__, got: __invalid_state__)');
  });

  it("should error when id_token can't be parsed", async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      nonce: '__valid_nonce__',
      state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__valid_state__',
          id_token: '__invalid_token__'
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (failed to decode JWT (JWTMalformed: JWTs must have three components))');
  });

  it('should error when id_token has invalid alg', async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      nonce: '__valid_nonce__',
      state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__valid_state__',
          id_token: JWT.sign({ sub: '__test_sub__' }, 'secret', {
            algorithm: 'HS256'
          })
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (unexpected JWT alg received, expected RS256, got: HS256)');
  });

  it('should error when id_token is missing issuer', async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      nonce: '__valid_nonce__',
      state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__valid_state__',
          id_token: makeIdToken({ iss: undefined })
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (missing required JWT property iss)');
  });

  it('should error when nonce is missing from cookies', async () => {
    await setup(defaultConfig);

    const cookieJar = await cookies({
      state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__valid_state__',
          id_token: makeIdToken({ nonce: '__test_nonce__' })
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (nonce mismatch, expected undefined, got: __test_nonce__)');
  });

  it('should error when legacy samesite fallback is off', async () => {
    await setup({ ...defaultConfig, legacySameSiteCookie: false });

    const cookieJar = await cookies({
      _state: '__valid_state__'
    });

    await expect(
      got.post('callback', {
        json: {
          state: '__valid_state__',
          id_token: makeIdToken()
        },
        cookieJar
      })
    ).rejects.toThrowError('Response code 400 (checks.state argument is missing)');
  });

  it('should expose the id token claims when id_token is valid', async () => {
    await setup({ ...defaultConfig, legacySameSiteCookie: false });

    const expected = {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: '__test_client_id__',
      nonce: '__test_nonce__'
    };

    const cookieJar = await cookies({
      state: expectedDefaultState,
      nonce: '__test_nonce__'
    });

    const callback = await got.post('callback', {
      json: {
        state: expectedDefaultState,
        id_token: makeIdToken(expected)
      },
      cookieJar,
      followRedirect: false
    });
    const response = got.get('me', { cookieJar });
    const actual = await response.json();

    expect(callback.statusCode).toEqual(302);
    expect(actual).toEqual(expect.objectContaining(expected));
  });

  // it("should expose all tokens when id_token is valid and response_type is 'code id_token'", async () => {
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //
  //   const { tokens } = await setup({
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code id_token',
  //         audience: 'https://api.example.com/',
  //         scope: 'openid profile email read:reports offline_access'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //
  //   assert.equal(tokens.isAuthenticated, true);
  //   assert.equal(tokens.idToken, idToken);
  //   assert.equal(tokens.refreshToken, '__test_refresh_token__');
  //   assert.include(tokens.accessToken, {
  //     access_token: '__test_access_token__',
  //     token_type: 'Bearer'
  //   });
  //   assert.include(tokens.idTokenClaims, {
  //     sub: '__test_sub__'
  //   });
  // });
  //
  // it('should handle access token expiry', async () => {
  //   const clock = sinon.useFakeTimers({ toFake: ['Date'] });
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //   const hrSecs = 60 * 60;
  //   const hrMs = hrSecs * 1000;
  //
  //   const { tokens, jar } = await setup({
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //   assert.equal(tokens.accessToken.expires_in, 24 * hrSecs);
  //   clock.tick(4 * hrMs);
  //   const tokens2 = await request.get('/tokens', { baseUrl, jar, json: true }).then((r) => r.body);
  //   assert.equal(tokens2.accessToken.expires_in, 20 * hrSecs);
  //   assert.isFalse(tokens2.accessTokenExpired);
  //   clock.tick(21 * hrMs);
  //   const tokens3 = await request.get('/tokens', { baseUrl, jar, json: true }).then((r) => r.body);
  //   assert.isTrue(tokens3.accessTokenExpired);
  //   clock.restore();
  // });
  //
  // it('should refresh an access token', async () => {
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //
  //   const authOpts = {
  //     ...defaultConfig,
  //     clientSecret: '__test_client_secret__',
  //     authorizationParams: {
  //       response_type: 'code id_token',
  //       audience: 'https://api.example.com/',
  //       scope: 'openid profile email read:reports offline_access'
  //     }
  //   };
  //   const router = auth(authOpts);
  //   router.get('/refresh', async (req, res) => {
  //     const accessToken = await req.oidc.accessToken.refresh();
  //     res.json({
  //       accessToken,
  //       refreshToken: req.oidc.refreshToken
  //     });
  //   });
  //
  //   const { tokens, jar } = await setup({
  //     router,
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code id_token',
  //         audience: 'https://api.example.com/',
  //         scope: 'openid profile email read:reports offline_access'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //
  //   const reply = sinon.spy(() => ({
  //     access_token: '__new_access_token__',
  //     refresh_token: '__new_refresh_token__',
  //     id_token: tokens.idToken,
  //     token_type: 'Bearer',
  //     expires_in: 86400
  //   }));
  //   const {
  //     interceptors: [interceptor]
  //   } = nock('https://op.example.com', { allowUnmocked: true }).post('/oauth/token').reply(200, reply);
  //
  //   const newTokens = await request.get('/refresh', { baseUrl, jar, json: true }).then((r) => r.body);
  //   nock.removeInterceptor(interceptor);
  //
  //   sinon.assert.calledWith(reply, '/oauth/token', 'grant_type=refresh_token&refresh_token=__test_refresh_token__');
  //
  //   assert.equal(tokens.accessToken.access_token, '__test_access_token__');
  //   assert.equal(tokens.refreshToken, '__test_refresh_token__');
  //   assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
  //   assert.equal(newTokens.refreshToken, '__new_refresh_token__');
  //
  //   const newerTokens = await request.get('/tokens', { baseUrl, jar, json: true }).then((r) => r.body);
  //
  //   assert.equal(
  //     newerTokens.accessToken.access_token,
  //     '__new_access_token__',
  //     'the new access token should be persisted in the session'
  //   );
  // });
  //
  // it('should refresh an access token and keep original refresh token', async () => {
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //
  //   const authOpts = {
  //     ...defaultConfig,
  //     clientSecret: '__test_client_secret__',
  //     authorizationParams: {
  //       response_type: 'code id_token',
  //       audience: 'https://api.example.com/',
  //       scope: 'openid profile email read:reports offline_access'
  //     }
  //   };
  //   const router = auth(authOpts);
  //   router.get('/refresh', async (req, res) => {
  //     const accessToken = await req.oidc.accessToken.refresh();
  //     res.json({
  //       accessToken,
  //       refreshToken: req.oidc.refreshToken
  //     });
  //   });
  //
  //   const { tokens, jar } = await setup({
  //     router,
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code id_token',
  //         audience: 'https://api.example.com/',
  //         scope: 'openid profile email read:reports offline_access'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //
  //   const reply = sinon.spy(() => ({
  //     access_token: '__new_access_token__',
  //     id_token: tokens.id_token,
  //     token_type: 'Bearer',
  //     expires_in: 86400
  //   }));
  //   const {
  //     interceptors: [interceptor]
  //   } = nock('https://op.example.com', { allowUnmocked: true }).post('/oauth/token').reply(200, reply);
  //
  //   const newTokens = await request.get('/refresh', { baseUrl, jar, json: true }).then((r) => r.body);
  //   nock.removeInterceptor(interceptor);
  //
  //   sinon.assert.calledWith(reply, '/oauth/token', 'grant_type=refresh_token&refresh_token=__test_refresh_token__');
  //
  //   assert.equal(tokens.accessToken.access_token, '__test_access_token__');
  //   assert.equal(tokens.refreshToken, '__test_refresh_token__');
  //   assert.equal(newTokens.accessToken.access_token, '__new_access_token__');
  //   assert.equal(newTokens.refreshToken, '__test_refresh_token__');
  // });
  //
  // it('should fetch userinfo', async () => {
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //
  //   const authOpts = {
  //     ...defaultConfig,
  //     clientSecret: '__test_client_secret__',
  //     authorizationParams: {
  //       response_type: 'code id_token',
  //       audience: 'https://api.example.com/',
  //       scope: 'openid profile email'
  //     }
  //   };
  //   const router = auth(authOpts);
  //   router.get('/user-info', async (req, res) => {
  //     res.json(await req.oidc.fetchUserInfo());
  //   });
  //
  //   const { jar } = await setup({
  //     router,
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code id_token',
  //         audience: 'https://api.example.com/',
  //         scope: 'openid profile email read:reports offline_access'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //
  //   const {
  //     interceptors: [interceptor]
  //   } = nock('https://op.example.com', { allowUnmocked: true })
  //     .get('/userinfo')
  //     .reply(200, () => ({
  //       userInfo: true,
  //       sub: '__test_sub__'
  //     }));
  //
  //   const userInfo = await request.get('/user-info', { baseUrl, jar, json: true }).then((r) => r.body);
  //
  //   nock.removeInterceptor(interceptor);
  //
  //   assert.deepEqual(userInfo, { userInfo: true, sub: '__test_sub__' });
  // });
  //
  // it('should use basic auth on token endpoint when using code flow', async () => {
  //   const idToken = makeIdToken({
  //     c_hash: '77QmUPtjPfzWtF2AnpK9RQ'
  //   });
  //
  //   const { tokenReqBody, tokenReqHeader } = await setup({
  //     authOpts: {
  //       clientSecret: '__test_client_secret__',
  //       authorizationParams: {
  //         response_type: 'code id_token',
  //         audience: 'https://api.example.com/',
  //         scope: 'openid profile email read:reports offline_access'
  //       }
  //     },
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken,
  //       code: 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'
  //     }
  //   });
  //
  //   const credentials = Buffer.from(tokenReqHeader.authorization.replace('Basic ', ''), 'base64');
  //   assert.equal(credentials, '__test_client_id__:__test_client_secret__');
  //   assert.match(tokenReqBody, /code=jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y/);
  // });
  //
  // it('should resume silent logins when user successfully logs in', async () => {
  //   const idToken = makeIdToken();
  //   const jar = request.jar();
  //   jar.setCookie('skipSilentLogin=true', baseUrl);
  //   await setup({
  //     cookies: {
  //       _state: expectedDefaultState,
  //       _nonce: '__test_nonce__',
  //       skipSilentLogin: '1'
  //     },
  //     body: {
  //       state: expectedDefaultState,
  //       id_token: idToken
  //     },
  //     jar
  //   });
  //   const cookies = jar.getCookies(baseUrl);
  //   assert.notOk(cookies.find(({ key }) => key === 'skipSilentLogin'));
  // });
});
