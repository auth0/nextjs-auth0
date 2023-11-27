import { setup, teardown } from '../fixtures/server';
import { defaultConfig, post } from '../fixtures/helpers';
import { makeLogoutToken } from '../fixtures/cert';
import { isLoggedOut, getConfig } from '../../../src/auth0-session';

class Store {
  public store: { [key: string]: any };
  constructor() {
    this.store = {};
  }
  get(id: string) {
    return Promise.resolve(this.store[id]);
  }
  async set(id: string, val: any) {
    this.store[id] = val;
    await Promise.resolve();
  }
  async delete(id: string) {
    delete this.store[id];
    await Promise.resolve();
  }
}

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
});
