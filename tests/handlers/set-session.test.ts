import base64url from 'base64url';
import handlers from '../../src/handlers';
import { ISessionStore } from '../../src/session/store';
import getRequestResponse from '../helpers/http';

describe('set session handler', () => {
  let store: ISessionStore;

  const tokenSetParams = {
    access_token: 'my-access-token',
    refresh_token: 'my-refresh-token',
    id_token: `jwt-header.${base64url.encode(
      JSON.stringify({
        email: 'foo@bar.com',
        email_verified: false,
        name: 'Foo Bar',
        nickname: 'foobar',
        picture: 'http://example.com/image',
        sub: 'user-id',
        updated_at: '2020-12-01T12:15:06.383Z'
      })
    )}.my-verify-signature`,
    scope: 'openid profile email offline_access',
    expires_in: 2592000,
    token_type: 'Bearer'
  };

  beforeEach(() => {
    store = {
      read: jest.fn().mockResolvedValue({}),
      save: jest.fn().mockResolvedValue({})
    };
  });

  test('should require a truthy request object', async () => {
    const { res } = getRequestResponse();
    const sessionHandler = handlers.SetSessionHandler(store);

    await expect(sessionHandler(null as any, res, tokenSetParams)).rejects.toEqual(
      new Error('Request is not available')
    );
  });

  test('should require a truthy response object', async () => {
    const { req } = getRequestResponse();
    const sessionHandler = handlers.SetSessionHandler(store);

    await expect(sessionHandler(req, null as any, tokenSetParams)).rejects.toEqual(
      new Error('Response is not available')
    );
  });

  test('should set the session', async () => {
    const { req, res } = getRequestResponse();

    const setSessionHandler = handlers.SetSessionHandler(store);

    await setSessionHandler(req, res, tokenSetParams);

    expect(store.save).toHaveBeenCalledWith(req, res, {
      accessToken: 'my-access-token',
      accessTokenExpiresAt: expect.any(Number),
      accessTokenScope: 'openid profile email offline_access',
      createdAt: expect.any(Number),
      idToken:
        'jwt-header.eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiRm9vIEJhciIsIm5pY2tuYW1lIjoiZm9vYmFyIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9pbWFnZSIsInN1YiI6InVzZXItaWQiLCJ1cGRhdGVkX2F0IjoiMjAyMC0xMi0wMVQxMjoxNTowNi4zODNaIn0.my-verify-signature',
      refreshToken: 'my-refresh-token',
      user: {
        email: 'foo@bar.com',
        email_verified: false,
        name: 'Foo Bar',
        nickname: 'foobar',
        picture: 'http://example.com/image',
        sub: 'user-id',
        updated_at: '2020-12-01T12:15:06.383Z'
      }
    });
  });
});
