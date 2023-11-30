import { setup, teardown } from '../fixtures/server';
import { defaultConfig, post, Store } from '../fixtures/helpers';
import { makeLogoutToken } from '../fixtures/cert';
import { isLoggedOut, getConfig, deleteSub } from '../../../src/auth0-session';

describe('backchannel-logout', () => {
  afterEach(teardown);

  it('should fail when logout_token is missing', async () => {
    const params = { ...defaultConfig, session: { store: new Store(), genId: () => 'foo' } };
    const baseURL = await setup(params);
    await expect(post(baseURL, '/backchannel-logout', { body: {} })).rejects.toThrow('Missing Logout Token');
    await expect(isLoggedOut({ sid: 'foo' }, getConfig({ baseURL, ...params }))).resolves.toEqual(false);
  });

  it('should succeed with valid logout token', async () => {
    const store = new Store();
    const params = { ...defaultConfig, session: { store, genId: () => 'foo' } };
    const baseURL = await setup(params);
    const { res } = await post(baseURL, '/backchannel-logout', {
      body: { logout_token: await makeLogoutToken({ sid: 'foo' }) },
      fullResponse: true
    });
    await expect(store.get('sid|__test_client_id__|foo')).resolves.toMatchObject({
      header: {
        maxAge: 24 * 60 * 60 * 1000,
        exp: expect.any(Number)
      },
      data: {}
    });
    expect(res.statusCode).toEqual(204);
    await expect(isLoggedOut({ sid: 'foo' }, getConfig({ baseURL, ...params }))).resolves.toEqual(true);
  });

  it('should save sid and sub', async () => {
    const store = new Store();
    const params = { ...defaultConfig, session: { store, genId: () => 'foo' } };
    const baseURL = await setup(params);
    const { res } = await post(baseURL, '/backchannel-logout', {
      body: { logout_token: await makeLogoutToken({ sid: 'foo', sub: 'bar' }) },
      fullResponse: true
    });
    await expect(store.get('sid|__test_client_id__|foo')).resolves.toMatchObject({
      data: {}
    });
    await expect(store.get('sub|__test_client_id__|bar')).resolves.toMatchObject({
      data: {}
    });
    expect(res.statusCode).toEqual(204);
    await expect(isLoggedOut({ sid: 'foo' }, getConfig({ baseURL, ...params }))).resolves.toEqual(true);
    await expect(isLoggedOut({ sub: 'bar' }, getConfig({ baseURL, ...params }))).resolves.toEqual(true);
    await expect(isLoggedOut({ sid: 'foo', sub: 'bar' }, getConfig({ baseURL, ...params }))).resolves.toEqual(true);
    await expect(isLoggedOut({ sub: 'foo', sid: 'bar' }, getConfig({ baseURL, ...params }))).resolves.toEqual(false);
  });

  it('should save just sub', async () => {
    const store = new Store();
    const params = { ...defaultConfig, session: { store, genId: () => 'foo' } };
    const baseURL = await setup(params);
    const { res } = await post(baseURL, '/backchannel-logout', {
      body: { logout_token: await makeLogoutToken({ sub: 'bar' }) },
      fullResponse: true
    });
    await expect(store.get('sub|__test_client_id__|bar')).resolves.toMatchObject({
      data: {}
    });
    expect(res.statusCode).toEqual(204);
    await expect(isLoggedOut({ sub: 'bar' }, getConfig({ baseURL, ...params }))).resolves.toEqual(true);
  });

  it('should fail when saving fails', async () => {
    const store = new Store();
    store.set = function () {
      throw new Error('saving failed');
    };
    const params = { ...defaultConfig, session: { store, genId: () => 'foo' } };
    const baseURL = await setup(params);
    await expect(
      post(baseURL, '/backchannel-logout', {
        body: { logout_token: await makeLogoutToken({ sub: 'bar' }) },
        fullResponse: true
      })
    ).rejects.toThrow('saving failed');
  });

  it('should save logout with absolute duration', async () => {
    const store = new Store();
    const baseURL = await setup({ ...defaultConfig, session: { store, genId: () => 'foo', rolling: false } });
    const { res } = await post(baseURL, '/backchannel-logout', {
      body: { logout_token: await makeLogoutToken({ sid: 'foo' }) },
      fullResponse: true
    });
    await expect(store.get('sid|__test_client_id__|foo')).resolves.toMatchObject({
      header: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        exp: expect.any(Number)
      },
      data: {}
    });
    expect(res.statusCode).toEqual(204);
  });

  it('should delete a sub entry from the logout store', async () => {
    const store = new Store();
    const config = getConfig({ ...defaultConfig, session: { store, genId: () => 'foo' }, baseURL: 'http://localhost' });
    await expect(isLoggedOut({ sub: 'bar' }, config)).resolves.toEqual(false);
    await store.set('sub|__test_client_id__|bar', {});
    await expect(isLoggedOut({ sub: 'bar' }, config)).resolves.toEqual(true);
    await deleteSub('bar', config);
    await expect(isLoggedOut({ sub: 'bar' }, config)).resolves.toEqual(false);
  });
});
