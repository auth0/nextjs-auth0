/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import { NextRequest, NextResponse } from 'next/server';
import { withApi } from '../fixtures/default-settings';
import { signCookie } from '../auth0-session/fixtures/helpers';
import { encodeState } from '../../src/auth0-session/utils/encoding';
import type { Session } from '../../src';
import { getResponse, mockFetch, getSession as getSessionFromRes } from '../fixtures/app-router-helpers';

describe('callback handler (app router)', () => {
  beforeEach(mockFetch);

  test('should require a state parameter', async () => {
    const res = await getResponse({
      url: '/api/auth/callback',
      cookies: {
        state: await signCookie('state', 'foo')
      }
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(/Missing state parameter|response parameter &quot;state&quot; missing/);
  });

  test('should require a state cookie', async () => {
    const res = await getResponse({
      url: '/api/auth/callback?state=__test_state__'
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(/Missing state cookie from login request/);
  });

  test('should validate the state', async () => {
    const res = await getResponse({
      url: '/api/auth/callback?state=__test_state__',
      cookies: {
        state: await signCookie('state', 'other_state')
      }
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(
      /state mismatch, expected other_state, got: __test_state__|unexpected &quot;state&quot; response parameter value/
    );
  });

  test('should validate the audience', async () => {
    const state = encodeState({ returnTo: 'https://example.com' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      },
      idTokenClaims: { aud: 'bar' }
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(
      /aud mismatch, expected __test_client_id__, got: bar|unexpected JWT "aud" \(audience\) claim value/
    );
  });

  test('should validate the issuer', async () => {
    const state = encodeState({ returnTo: 'https://example.com' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      },
      idTokenClaims: { iss: 'other-issuer' }
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(
      /unexpected iss value, expected https:\/\/acme.auth0.local\/, got: other-issuer|unexpected JWT "iss" \(issuer\) claim value/
    );
  });

  test('should escape html in error qp', async () => {
    const res = await getResponse({
      url: '/api/auth/callback?error=%3Cscript%3Ealert(%27xss%27)%3C%2Fscript%3E&state=foo',
      cookies: {
        state: await signCookie('state', 'foo')
      }
    });
    expect(res.status).toBe(400);
    expect(res.statusText).toMatch(/&lt;script&gt;alert\(&#39;xss&#39;\)&lt;\/script&gt;/);
  });

  test('should create session and strip OIDC claims', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      }
    });
    expect(res.status).toEqual(302);
    expect(res.headers.get('location')).toEqual('https://example.com/foo');
    const session = await getSessionFromRes(withApi, res);
    expect(session).toMatchObject({
      user: { sub: '__test_sub__' },
      accessToken: expect.any(String)
    });
    expect(session?.user).not.toHaveProperty('iss');
  });

  test('remove properties from session with afterCallback hook', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      },
      callbackOpts: {
        afterCallback(_req: NextRequest, session: Session) {
          delete session.accessToken;
          return session;
        }
      }
    });
    expect(res.status).toEqual(302);
    expect(res.headers.get('location')).toEqual('https://example.com/foo');
    const session = await getSessionFromRes(withApi, res);
    expect(session).toMatchObject({
      user: { sub: '__test_sub__' }
    });
    expect(session).not.toHaveProperty('accessToken');
  });

  test('add properties to session with afterCallback hook', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      },
      callbackOpts: {
        afterCallback(_req: NextRequest, session: Session) {
          return { ...session, foo: 'bar' };
        }
      }
    });
    expect(res.status).toEqual(302);
    expect(res.headers.get('location')).toEqual('https://example.com/foo');
    const session = await getSessionFromRes(withApi, res);
    expect(session).toMatchObject({
      user: { sub: '__test_sub__' },
      foo: 'bar'
    });
  });

  test('throws from afterCallback hook', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          afterCallback() {
            throw new Error('some validation error.');
          }
        }
      })
    ).resolves.toMatchObject({ status: 500, statusText: expect.stringMatching(/some validation error/) });
  });

  test('redirect from afterCallback hook', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    const res = await getResponse({
      url: `/api/auth/callback?state=${state}&code=code`,
      cookies: {
        state: await signCookie('state', state),
        nonce: await signCookie('nonce', '__test_nonce__'),
        code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
      },
      callbackOpts: {
        afterCallback() {
          return NextResponse.redirect('https://example.com/foo');
        }
      }
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://example.com/foo');
  });

  test('throws for missing org_id claim', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'org_foo'
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/Organization Id \(org_id\) claim must be a string present in the ID token/)
    });
  });

  test('throws for missing org_name claim', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'foo'
        }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(/Organization Name \(org_name\) claim must be a string present in the ID token/)
    });
  });

  test('throws for org_id claim mismatch', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'org_foo'
        },
        idTokenClaims: { org_id: 'org_bar' }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(
        /Organization Id \(org_id\) claim value mismatch in the ID token; expected "org_foo", found "org_bar"/
      )
    });
  });

  test('throws for org_name claim mismatch', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'foo'
        },
        idTokenClaims: { org_name: 'bar' }
      })
    ).resolves.toMatchObject({
      status: 500,
      statusText: expect.stringMatching(
        /Organization Name \(org_name\) claim value mismatch in the ID token; expected "foo", found "bar"/
      )
    });
  });

  test('accepts a valid organization id', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'org_foo'
        },
        idTokenClaims: { org_id: 'org_foo' }
      })
    ).resolves.toMatchObject({
      status: 302
    });
  });

  test('accepts a valid organization name', async () => {
    const state = encodeState({ returnTo: 'https://example.com/foo' });
    await expect(
      getResponse({
        url: `/api/auth/callback?state=${state}&code=code`,
        cookies: {
          state: await signCookie('state', state),
          nonce: await signCookie('nonce', '__test_nonce__'),
          code_verifier: await signCookie('code_verifier', '__test_code_verifier__')
        },
        callbackOpts: {
          organization: 'foo'
        },
        idTokenClaims: { org_name: 'foo' }
      })
    ).resolves.toMatchObject({
      status: 302
    });
  });
});
