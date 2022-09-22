import { IncomingMessage, ServerResponse } from 'http';
import { ArgumentsOf } from 'ts-jest';
import { withoutApi } from '../fixtures/default-settings';
import { setup, teardown } from '../fixtures/setup';
import { get, post } from '../auth0-session/fixtures/helpers';
import {
  CallbackOptions,
  HandleCallback,
  HandleLogin,
  HandleLogout,
  HandleProfile,
  initAuth0,
  LoginOptions,
  LogoutOptions,
  OnError,
  ProfileOptions
} from '../../src';
import * as loginHandler from '../../src/handlers/login';
import * as logoutHandler from '../../src/handlers/logout';
import * as callbackHandler from '../../src/handlers/callback';
import * as profileHandler from '../../src/handlers/profile';

const handlerError = (status = 400, error = 'foo', error_description = 'bar') =>
  expect.objectContaining({
    status,
    cause: expect.objectContaining({ error, error_description })
  });

describe('auth handler', () => {
  afterEach(teardown);

  test('return 500 for unexpected error', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
    delete global.onError;
    jest.spyOn(console, 'error').mockImplementation((error) => {
      delete error.status;
    });
    await expect(get(baseUrl, '/api/auth/callback?error=foo&error_description=bar')).rejects.toThrow(
      'Internal Server Error'
    );
  });

  test('return 404 for unknown routes', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
    await expect(get(baseUrl, '/api/auth/foo')).rejects.toThrow('Not Found');
  });
});

describe('custom error handler', () => {
  afterEach(teardown);

  test('accept custom error handler', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.end());
    const baseUrl = await setup(withoutApi, { onError });
    await get(baseUrl, '/api/auth/callback?error=foo&error_description=bar');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('use default error handler', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
    delete global.onError;
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    jest.spyOn(console, 'error').mockImplementation(() => {});
    await expect(get(baseUrl, '/api/auth/callback?error=foo&error_description=bar')).rejects.toThrow('Bad Request');
    expect(console.error).toHaveBeenCalledWith(new Error('Callback handler failed. CAUSE: foo (bar)'));
  });

  test('finish response if custom error does not', async () => {
    const onError = jest.fn();
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar', { fullResponse: true })
    ).rejects.toThrow('Internal Server Error');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('finish response with custom error status', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.status(418));
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar', { fullResponse: true })
    ).rejects.toThrow("I'm a Teapot");
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });
});

describe('custom handlers', () => {
  afterEach(teardown);

  test('accept custom login handler', async () => {
    const spyHandler: HandleLogin = jest.fn(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi, { loginHandler: spyHandler });
    await get(baseUrl, '/api/auth/login');
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom logout handler', async () => {
    const spyHandler: HandleLogout = jest.fn(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi, { logoutHandler: spyHandler });
    await get(baseUrl, '/api/auth/logout');
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom callback handler', async () => {
    const spyHandler: HandleCallback = jest.fn(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi, { callbackHandler: spyHandler });
    await post(baseUrl, '/api/auth/callback', { body: {} });
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom profile handler', async () => {
    const spyHandler: HandleProfile = jest.fn(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi, { profileHandler: spyHandler });
    await post(baseUrl, '/api/auth/me', { body: {} });
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });
});

describe('custom options', () => {
  const spyHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
    res.end();
  });

  afterEach(teardown);

  test('accept custom login options', async () => {
    jest.spyOn(loginHandler, 'default').mockImplementation(() => spyHandler);
    const loginOptions: LoginOptions = {
      authorizationParams: { scope: 'openid' }
    };
    const baseUrl = await setup(withoutApi, { loginOptions });
    await get(baseUrl, '/api/auth/login');
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), loginOptions);
  });

  test('accept custom logout options', async () => {
    jest.spyOn(logoutHandler, 'default').mockImplementation(() => spyHandler);
    const logoutOptions: LogoutOptions = { returnTo: 'https://example.com' };
    const baseUrl = await setup(withoutApi, { logoutOptions });
    await get(baseUrl, '/api/auth/logout');
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), logoutOptions);
  });

  test('accept custom callback options', async () => {
    jest.spyOn(callbackHandler, 'default').mockImplementation(() => spyHandler);
    const callbackOptions: CallbackOptions = { authorizationParams: { scope: 'openid' } };
    const baseUrl = await setup(withoutApi, { callbackOptions });
    await post(baseUrl, '/api/auth/callback', { body: {} });
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), callbackOptions);
  });

  test('accept custom profile options', async () => {
    jest.spyOn(profileHandler, 'default').mockImplementation(() => spyHandler);
    const profileOptions: ProfileOptions = { refetch: true };
    const baseUrl = await setup(withoutApi, { profileOptions });
    await post(baseUrl, '/api/auth/me', { body: {} });
    expect(spyHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), profileOptions);
  });
});
