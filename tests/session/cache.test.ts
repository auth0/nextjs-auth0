import { IncomingMessage, ServerResponse } from 'http';
import { Socket } from 'net';
import { StatelessSession } from '../../src/auth0-session';
import { getConfig } from '../../src/config';
import { get, set } from '../../src/session/cache';
import { ConfigParameters, Session, SessionCache } from '../../src';
import { withoutApi } from '../fixtures/default-settings';

describe('SessionCache', () => {
  let cache: SessionCache;
  let req: IncomingMessage;
  let res: ServerResponse;
  let session: Session;
  let sessionStore: StatelessSession<Session>;

  const setup = (conf: ConfigParameters) => {
    const config = getConfig(conf);
    sessionStore = jest.mocked(new StatelessSession(config));
    sessionStore.save = jest.fn();
    session = new Session({ sub: '__test_user__' });
    session.idToken = '__test_id_token__';
    cache = new SessionCache(() => config);
    cache.getSessionStore = () => sessionStore;
    req = jest.mocked(new IncomingMessage(new Socket()));
    res = jest.mocked(new ServerResponse(req));
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
    expect(sessionStore.save).toHaveBeenCalledWith(
      expect.objectContaining({ req }),
      expect.objectContaining({ res }),
      session,
      undefined
    );
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
    sessionStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect(await cache.isAuthenticated(req, res)).toEqual(true);
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__test_user__' });
    await cache.set(req, res, new Session({ sub: '__new_user__' }));
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__new_user__' });
    expect(sessionStore.read).toHaveBeenCalledTimes(1);
    expect(sessionStore.save).toHaveBeenCalledTimes(2);
  });

  test('should save the session only on update without a rolling session', async () => {
    setup({ ...withoutApi, session: { rolling: false } });
    sessionStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect(await cache.isAuthenticated(req, res)).toEqual(true);
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__test_user__' });
    cache.set(req, res, new Session({ sub: '__new_user__' }));
    expect((await cache.get(req, res))?.user).toEqual({ sub: '__new_user__' });
    expect(sessionStore.read).toHaveBeenCalledTimes(1);
    expect(sessionStore.save).toHaveBeenCalledTimes(1);
  });

  test('should save the session on read and update with a rolling session from RSC', async () => {
    sessionStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect((await get({ sessionCache: cache }))[0]?.user).toEqual({ sub: '__test_user__' });
    await set({ sessionCache: cache, session: new Session({ sub: '__new_user__' }) });
    // Note: the cache is not updated from a RSC as there is no request context to cache against
    expect((await get({ sessionCache: cache }))[0]?.user).toEqual({ sub: '__test_user__' });
    expect(sessionStore.read).toHaveBeenCalledTimes(2);
    expect(sessionStore.save).toHaveBeenCalledTimes(3);
  });

  test('should save the session only on update without a rolling session from RSC', async () => {
    setup({ ...withoutApi, session: { rolling: false } });
    sessionStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    expect((await get({ sessionCache: cache }))[0]?.user).toEqual({ sub: '__test_user__' });
    await set({ session: new Session({ sub: '__new_user__' }), sessionCache: cache });
    expect((await get({ sessionCache: cache }))[0]?.user).toEqual({ sub: '__test_user__' });
    expect(sessionStore.read).toHaveBeenCalledTimes(2);
    expect(sessionStore.save).toHaveBeenCalledTimes(1);
  });

  test('should get an instance of Session from an RSC', async () => {
    sessionStore.read = jest.fn().mockResolvedValue([{ user: { sub: '__test_user__' } }, 500]);
    const [session] = await get({ sessionCache: cache });
    expect(session).toBeInstanceOf(Session);
  });
});
