import { NextApiRequest, NextApiResponse } from 'next';

import handlers from '../../src/handlers';
import { ISession } from '../../src/session/session';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';

describe('require authentication handle handler', () => {
  const apiRoute = async (_: NextApiRequest, res: NextApiResponse): Promise<void> => {
    await Promise.resolve();
    res.json({
      foo: 'bar'
    });
  };

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
      const requireAuthenticationHandler = handlers.RequireAuthentication(store);

      const req: any = null;
      const { res } = getRequestResponse();

      return expect(requireAuthenticationHandler(apiRoute)(req, res)).rejects.toEqual(
        new Error('Request is not available')
      );
    });

    test('should throw an error if the response is null', async () => {
      const store = getStore();
      const requireAuthenticationHandler = handlers.RequireAuthentication(store);

      const { req } = getRequestResponse();
      const res: any = null;

      return expect(requireAuthenticationHandler(apiRoute)(req, res)).rejects.toEqual(
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
      refreshToken: 'my-refresh-token',
      createdAt: Date.now()
    });

    const { req, res, jsonFn } = getRequestResponse();

    test('should execute the API route', async () => {
      const requireAuthenticationHandler = handlers.RequireAuthentication(store);
      await requireAuthenticationHandler(apiRoute)(req, res);

      expect(jsonFn).toBeCalledWith({
        foo: 'bar'
      });
    });
  });

  describe('when not signed in', () => {
    const store = getStore();
    const {
      req, res, jsonFn, statusFn
    } = getRequestResponse();

    test('should return not authenticated', async () => {
      const requireAuthenticationHandler = handlers.RequireAuthentication(store);
      await requireAuthenticationHandler(apiRoute)(req, res);

      expect(statusFn).toBeCalledWith(401);
      expect(jsonFn).toBeCalledWith({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
    });
  });
});
