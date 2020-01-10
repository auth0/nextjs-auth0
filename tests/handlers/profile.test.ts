import { withoutApi } from '../helpers/default-settings';
import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';
import getClient from '../../src/utils/oidc-client';
import { userInfo, discovery } from '../helpers/oidc-nocks';

describe('profile handler', () => {
  const getStore = (session?: ISession, saveStore?: jest.Mock): ISessionStore => {
    const store: ISessionStore = {
      read(): Promise<ISession | null | undefined> {
        return Promise.resolve(session);
      },
      save(): Promise<ISession | null | undefined> {
        return Promise.resolve(session);
      }
    };

    if (saveStore) {
      store.save = saveStore;
    }

    return store;
  };

  describe('when the call is invalid', () => {
    test('should throw an error if the request is null', async () => {
      const store = getStore();
      const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));

      const req: any = null;
      const { res } = getRequestResponse();

      return expect(profileHandler(req, res)).rejects.toEqual(new Error('Request is not available'));
    });

    test('should throw an error if the response is null', async () => {
      const store = getStore();
      const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));

      const { req } = getRequestResponse();
      const res: any = null;

      return expect(profileHandler(req, res)).rejects.toEqual(new Error('Response is not available'));
    });
  });

  describe('when signed in', () => {
    describe('when not asked to refetch', () => {
      const store = getStore({
        user: {
          sub: '123'
        },
        idToken: 'my-id-token',
        accessToken: 'my-access-token',
        refreshToken: 'my-refresh-token',
        createdAt: Date.now()
      });

      const { req, res, jsonFn } = getRequestResponse();

      test('should return the profile', async () => {
        const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));
        await profileHandler(req, res);

        expect(jsonFn).toBeCalledWith({
          sub: '123'
        });
      });
    });

    describe('when asked to refetch', () => {
      test('should throw an error if the accessToken is missing', async () => {
        const store = getStore({
          user: {
            sub: '123'
          },
          createdAt: Date.now()
        });

        const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));
        const { req, res } = getRequestResponse();

        return expect(profileHandler(req, res, { refetch: true })).rejects.toEqual(
          new Error('The user does not have a valid access token.')
        );
      });

      test('should refetch the user and update the session', async () => {
        const now = Date.now();
        const saveStore = jest.fn();
        const session = {
          user: {
            sub: '123',
            someCustomClaim: 'someCustomValue',
            email_verified: false
          },
          accessToken: 'my-access-token',
          accessTokenExpiresAt: now + 60 * 1000,
          createdAt: now
        };
        const store = getStore(session, saveStore);

        userInfo(withoutApi, 'my-access-token', {
          sub: '123',
          email: 'something@something.com',
          email_verified: true
        });

        discovery(withoutApi);

        const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));
        const { req, res, jsonFn } = getRequestResponse();
        await profileHandler(req, res, { refetch: true });

        // Saves the new user in the session and merge the updated info with new values.
        expect(saveStore.mock.calls[0][2]).toEqual({
          user: {
            sub: '123',
            someCustomClaim: 'someCustomValue',
            email: 'something@something.com',
            email_verified: true
          },
          accessToken: 'my-access-token',
          accessTokenExpiresAt: now + 60 * 1000,
          createdAt: now
        });

        // Returns the new user
        expect(jsonFn).toBeCalledWith({
          sub: '123',
          someCustomClaim: 'someCustomValue',
          email: 'something@something.com',
          email_verified: true
        });
      });
    });
  });

  describe('when not signed in', () => {
    const store = getStore();
    const { req, res, jsonFn, statusFn } = getRequestResponse();

    test('should return not authenticated', async () => {
      const profileHandler = handlers.ProfileHandler(store, getClient(withoutApi));
      await profileHandler(req, res);

      expect(statusFn).toBeCalledWith(401);
      expect(jsonFn).toBeCalledWith({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
    });
  });
});
