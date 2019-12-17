import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';

describe('session handler', () => {
  test('should return the session', async () => {
    const now = Date.now();
    const { req, res } = getRequestResponse();

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
      save(): Promise<ISession | null | undefined> {
        return Promise.resolve(session);
      }
    };

    const sessionHandler = handlers.SessionHandler(store);
    const session = await sessionHandler(req, res);
    expect(session).toEqual({
      user: { sub: '123' },
      createdAt: now,
      idToken: 'my-id-token',
      refreshToken: 'my-refresh-token'
    });
  });
});
