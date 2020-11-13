import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/cache';
import getRequestResponse from '../helpers/http';

describe('session handler', () => {
  test('should return the session', async () => {
    const now = Date.now();
    const { req } = getRequestResponse();

    const store: ISessionStore = {
      read(): Promise<ISession | null> {
        return Promise.resolve({
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token'
        });
      },
      save(): Promise<ISession> {
        return Promise.resolve({
          user: {
            sub: '123'
          },
          createdAt: now,
          idToken: 'my-id-token',
          refreshToken: 'my-refresh-token'
        });
      }
    };

    const sessionHandler = handlers.SessionHandler(store);
    const session = await sessionHandler(req);
    expect(session).toEqual({
      user: { sub: '123' },
      createdAt: now,
      idToken: 'my-id-token',
      refreshToken: 'my-refresh-token'
    });
  });
});
