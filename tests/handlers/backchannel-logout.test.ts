/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import { getResponse, mockFetch } from '../fixtures/app-router-helpers';
import { Store } from '../auth0-session/fixtures/helpers';
import { makeLogoutToken } from '../auth0-session/fixtures/cert';

describe('backchannel-logout handler (app router)', () => {
  beforeEach(mockFetch);

  test('should 404 when backchannel logout is disabled', async () => {
    await expect(
      getResponse({ url: '/api/auth/backchannel-logout', reqInit: { method: 'post' } })
    ).resolves.toMatchObject({ status: 404 });
  });

  test('should error when misconfigured', async () => {
    const res = await getResponse({
      config: { backchannelLogout: true },
      url: '/api/auth/backchannel-logout',
      reqInit: { method: 'post' }
    });
    await expect(res.json()).resolves.toEqual({
      error: 'unknown_error',
      error_description:
        // eslint-disable-next-line max-len
        'Back-Channel Logout requires a "backchannelLogout.store" (you can also reuse "session.store" if you have stateful sessions).'
    });
  });

  test('should error when no logout token is provided', async () => {
    const res = await getResponse({
      config: { backchannelLogout: { store: new Store() } },
      url: '/api/auth/backchannel-logout',
      reqInit: { method: 'post' }
    });
    await expect(res.json()).resolves.toEqual({
      error: 'invalid_request',
      error_description: 'Missing Logout Token'
    });
  });

  test('should error when an invalid logout token is provided', async () => {
    const res = await getResponse({
      config: { backchannelLogout: { store: new Store() } },
      url: '/api/auth/backchannel-logout',
      reqInit: { method: 'post', body: 'logout_token=foo' }
    });
    await expect(res.json()).resolves.toEqual({
      error: 'invalid_request',
      error_description: 'Invalid Compact JWS'
    });
  });

  test('should succeed when a valid logout token is provided', async () => {
    const logoutToken = await makeLogoutToken({ iss: 'https://acme.auth0.local/', sid: 'foo' });
    const res = await getResponse({
      config: { backchannelLogout: { store: new Store() } },
      url: '/api/auth/backchannel-logout',
      reqInit: { method: 'post', body: `logout_token=${logoutToken}` }
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  test('should fail when logout token validation fails', async () => {
    const logoutToken = await makeLogoutToken({ iss: 'https://acme.auth0.local/', sid: 'foo', events: null });
    const res = await getResponse({
      config: { backchannelLogout: { store: new Store() } },
      url: '/api/auth/backchannel-logout',
      reqInit: { method: 'post', body: `logout_token=${logoutToken}` }
    });
    await expect(res.json()).resolves.toEqual({
      error: 'invalid_request',
      error_description: '"events" claim must be an object'
    });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  test('should save tokens into the store when a valid logout token is provided', async () => {
    const store = new Store();
    const logoutToken = await makeLogoutToken({ iss: 'https://acme.auth0.local/', sid: 'foo', sub: 'bar' });
    await expect(
      getResponse({
        config: { backchannelLogout: { store } },
        url: '/api/auth/backchannel-logout',
        reqInit: { method: 'post', body: `logout_token=${logoutToken}` }
      })
    ).resolves.toMatchObject({ status: 204 });
    await expect(store.get('sid|__test_client_id__|foo')).resolves.toMatchObject({ data: {} });
    await expect(store.get('sub|__test_client_id__|bar')).resolves.toMatchObject({ data: {} });
  });
});
