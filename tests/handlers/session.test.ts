import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';

describe('session handler', () => {
  test('should return the session', async () => {
    const { req } = getRequestResponse();
    const store: ISessionStore = {
      read(): Promise<ISession | null> {
        return Promise.resolve({
          sub: '123',
          idToken: 'my-id-token'
        });
      },
      save(): Promise<void> {
        return Promise.resolve();
      }
    };

    const sessionHandler = handlers.SessionHandler(store);
    const session = await sessionHandler(req);
    expect(session).toEqual({ sub: '123', idToken: 'my-id-token' });
  });
});
