import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';

describe('profile handler', () => {
  const getStore = (session?: ISession): ISessionStore => {
    const store: ISessionStore = {
      read(): Promise<ISession | null | undefined> {
        return Promise.resolve(session);
      },
      save(): Promise<void> {
        return Promise.resolve();
      }
    };
    return store;
  };

  describe('when the call is invalid', () => {
    test('should throw an error if the request is null', async () => {
      const store = getStore();
      const profileHandler = handlers.ProfileHandler(store);

      const req: any = null;
      const { res } = getRequestResponse();

      return expect(profileHandler(req, res)).rejects.toEqual(
        new Error('Request is not available')
      );
    });

    test('should throw an error if the response is null', async () => {
      const store = getStore();
      const profileHandler = handlers.ProfileHandler(store);

      const { req } = getRequestResponse();
      const res: any = null;

      return expect(profileHandler(req, res)).rejects.toEqual(
        new Error('Response is not available')
      );
    });
  });

  describe('when signed in', () => {
    const store = getStore({
      user: {
        sub: '123'
      },
      idToken: 'my-id-token',
      accessToken: 'my-access-token',
      createdAt: Date.now()
    });

    const { req, res, jsonFn } = getRequestResponse();

    test('should return the profile without any tokens', async () => {
      const profileHandler = handlers.ProfileHandler(store);
      await profileHandler(req, res);

      expect(jsonFn).toBeCalledWith({
        sub: '123'
      });
    });
  });

  describe('when not signed in', () => {
    const store = getStore();
    const {
      req, res, jsonFn, statusFn
    } = getRequestResponse();

    test('should return not authenticated', async () => {
      const profileHandler = handlers.ProfileHandler(store);
      await profileHandler(req, res);

      expect(statusFn).toBeCalledWith(401);
      expect(jsonFn).toBeCalledWith({
        error: 'Not authenticated'
      });
    });
  });
});
