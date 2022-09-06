import { IncomingMessage, ServerResponse } from 'http';
import { Socket } from 'net';
import { mocked } from 'ts-jest/utils';
import { Cookies, CookieStore, getConfig } from '../../src/auth0-session';
import { ConfigParameters, Session, SessionCache } from '../../src';
import { withoutApi } from '../fixtures/default-settings';

describe('SessionCache', () => {
  let cache: SessionCache;
  let req: IncomingMessage;
  let res: ServerResponse;
  let session: Session;
  let cookieStore: CookieStore;

  const setup = (conf: ConfigParameters) => {
    const config = getConfig(conf);
    cookieStore = mocked(new CookieStore(config, Cookies));
    cookieStore.save = jest.fn();
    session = new Session({ sub: '__test_user__' });
    session.idToken = '__test_id_token__';
    cache = new SessionCache(config, cookieStore);
    req = mocked(new IncomingMessage(new Socket()));
    res = mocked(new ServerResponse(req));
  };

  beforeEach(() => {
    setup(withoutApi);
  });

  test('should create an instance', () => {
    expect(cache).toBeInstanceOf(SessionCache);
  });

  test('should create the session entry', async () => {
    await cache.create(req, res, session);
    expect(await cache.get(req, res)).toEqual(session);
    expect(cookieStore.save).toHaveBeenCalledWith(req, res, session, undefined);
  });

  test('should delete the session entry', async () => {
    await cache.create(req, res, session);
    expect(await cache.get(req, res)).toEqual(session);
    await cache.delete(req, res);
    expect(await cache.get(req, res)).toBeNull();
  });

  test('should set authenticated for authenticated user', async () => {
    await cache.create(req, res, session);
    expect(await cache.isAuthenticated(req, res)).toEqual(true);
  });

  test('should set unauthenticated for anonymous user', async () => {
    expect(await cache.isAuthenticated(req, res)).toEqual(false);
  });

  test('should get an id token for authenticated user', async () => {
    await cache.create(req, res, session);
    expect(await cache.getIdToken(req, res)).toEqual('__test_id_token__');
  });

  test('should get no id token for anonymous user', async () => {
    expect(await cache.getIdToken(req, res)).toBeUndefined();
  });

  test('should save the session on read and update with a rolling session', async () => {
    cookieStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect(await cache.isAuthenticated(req, res)).toEqual(true);
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__test_user__' });
    await cache.set(req, res, new Session({ sub: '__new_user__' }));
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__new_user__' });
    expect(cookieStore.read).toHaveBeenCalledTimes(1);
    expect(cookieStore.save).toHaveBeenCalledTimes(2);
  });

  test('should save the session only on update without a rolling session', async () => {
    setup({ ...withoutApi, session: { rolling: false } });
    cookieStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect(await cache.isAuthenticated(req, res)).toEqual(true);
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__test_user__' });
    cache.set(req, res, new Session({ sub: '__new_user__' }));
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__new_user__' });
    expect(cookieStore.read).toHaveBeenCalledTimes(1);
    expect(cookieStore.save).toHaveBeenCalledTimes(1);
  });
});
