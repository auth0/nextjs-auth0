import { IncomingMessage, ServerResponse } from 'http';
import { ArgumentsOf } from 'ts-jest';
import { withoutApi } from '../fixtures/default-settings';
import { login, setup, teardown } from '../fixtures/setup';
import { get } from '../auth0-session/fixtures/helpers';
import { initAuth0, OnError, Session } from '../../src';
import { LoginHandler, LoginOptions } from '../../src/handlers/login';
import { LogoutHandler, LogoutOptions } from '../../src/handlers/logout';
import { CallbackHandler, CallbackOptions } from '../../src/handlers/callback';
import { ProfileHandler, ProfileOptions } from '../../src/handlers/profile';
import * as baseLoginHandler from '../../src/auth0-session/handlers/login';
import * as baseLogoutHandler from '../../src/auth0-session/handlers/logout';
import * as baseCallbackHandler from '../../src/auth0-session/handlers/callback';

const handlerError = () =>
  expect.objectContaining({
    status: 400,
    code: 'ERR_CALLBACK_HANDLER_FAILURE'
  });

describe('auth handler', () => {
  afterEach(teardown);

  test('return 500 for unexpected error', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth;
    delete global.onError;
    jest.spyOn(console, 'error').mockImplementation((error) => {
      delete error.status;
    });
    await expect(get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo')).rejects.toThrow(
      'Internal Server Error'
    );
  });

  test('return 404 for unknown routes', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth;
    await expect(get(baseUrl, '/api/auth/foo')).rejects.toThrow('Not Found');
  });
});

describe('custom error handler', () => {
  afterEach(teardown);

  test('accept custom error handler', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.end());
    const baseUrl = await setup(withoutApi, { onError });
    await get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('use default error handler', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth;
    delete global.onError;
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    jest.spyOn(console, 'error').mockImplementation(() => {});
    await expect(get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo')).rejects.toThrow(
      'Bad Request'
    );
    expect(console.error).toHaveBeenCalledWith(handlerError());
  });

  test('finish response if custom error does not', async () => {
    const onError = jest.fn();
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo', { fullResponse: true })
    ).rejects.toThrow('Internal Server Error');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('finish response with custom error status', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.status(418));
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo', { fullResponse: true })
    ).rejects.toThrow("I'm a Teapot");
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });
});

describe('custom handlers', () => {
  afterEach(teardown);

  test('accept custom login handler', async () => {
    const login = jest.fn<Promise<void>, ArgumentsOf<LoginHandler>>(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { login });
    await get(baseUrl, '/api/auth/login');
    expect(login).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom logout handler', async () => {
    const logout = jest.fn<Promise<void>, ArgumentsOf<LogoutHandler>>(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { logout });
    await get(baseUrl, '/api/auth/logout');
    expect(logout).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom callback handler', async () => {
    const callback = jest.fn<Promise<void>, ArgumentsOf<CallbackHandler>>(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { callback });
    await get(baseUrl, '/api/auth/callback');
    expect(callback).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom profile handler', async () => {
    const profile = jest.fn<Promise<void>, ArgumentsOf<ProfileHandler>>(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { profile });
    await get(baseUrl, '/api/auth/me');
    expect(profile).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });

  test('accept custom arbitrary handler', async () => {
    const signup = jest.fn<Promise<void>, ArgumentsOf<LoginHandler>>(async (_req, res) => {
      res.end();
    });
    const baseUrl = await setup(withoutApi);
    global.handleAuth = initAuth0(withoutApi).handleAuth.bind(null, { signup });
    await get(baseUrl, '/api/auth/signup');
    expect(signup).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse));
  });
});

describe('custom options', () => {
  afterEach(teardown);

  test('accept custom login options', async () => {
    const loginHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseLoginHandler, 'default').mockImplementation(() => loginHandler);
    const options: LoginOptions = { authorizationParams: { scope: 'openid' } };
    const baseUrl = await setup(withoutApi);
    const { handleLogin, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      login: handleLogin(options)
    });
    await get(baseUrl, '/api/auth/login');
    expect(loginHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), options);
  });

  test('accept custom logout options', async () => {
    const logoutHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseLogoutHandler, 'default').mockImplementation(() => logoutHandler);
    const options: LogoutOptions = { returnTo: '/foo' };
    const baseUrl = await setup(withoutApi);
    const { handleLogout, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      logout: handleLogout(options)
    });
    await get(baseUrl, '/api/auth/logout');
    expect(logoutHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), options);
  });

  test('accept custom callback options', async () => {
    const callbackHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseCallbackHandler, 'default').mockImplementation(() => callbackHandler);
    const options: CallbackOptions = { redirectUri: '/foo' };
    const baseUrl = await setup(withoutApi);
    const { handleCallback, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      callback: handleCallback(options)
    });
    await get(baseUrl, '/api/auth/callback');
    expect(callbackHandler).toHaveBeenCalledWith(
      expect.any(IncomingMessage),
      expect.any(ServerResponse),
      expect.objectContaining(options)
    );
  });

  test('accept custom profile options', async () => {
    const afterRefetch = jest.fn(async (_req: IncomingMessage, _res: ServerResponse, session: Session) => session);
    const options: ProfileOptions = { refetch: true, afterRefetch };
    const baseUrl = await setup(withoutApi);
    const { handleProfile, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      profile: handleProfile(options)
    });
    const cookieJar = await login(baseUrl);
    await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(afterRefetch).toHaveBeenCalled();
  });
});

describe('custom options providers', () => {
  afterEach(teardown);

  test('accept custom login options provider', async () => {
    const loginHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseLoginHandler, 'default').mockImplementation(() => loginHandler);
    const options = { authorizationParams: { scope: 'openid' } };
    const optionsProvider = jest.fn(() => options);
    const baseUrl = await setup(withoutApi);
    const { handleLogin, handleAuth } = initAuth0(withoutApi);

    global.handleAuth = handleAuth.bind(null, {
      login: handleLogin(optionsProvider)
    });
    await get(baseUrl, '/api/auth/login');
    expect(optionsProvider).toHaveBeenCalled();
    expect(loginHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), options);
  });

  test('accept custom logout options provider', async () => {
    const logoutHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseLogoutHandler, 'default').mockImplementation(() => logoutHandler);
    const options: LogoutOptions = { returnTo: '/foo' };
    const optionsProvider = jest.fn(() => options);
    const baseUrl = await setup(withoutApi);
    const { handleLogout, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      logout: handleLogout(optionsProvider)
    });
    await get(baseUrl, '/api/auth/logout');
    expect(optionsProvider).toHaveBeenCalled();
    expect(logoutHandler).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), options);
  });

  test('accept custom callback options provider', async () => {
    const callbackHandler = jest.fn(async (_req: IncomingMessage, res: ServerResponse) => {
      res.end();
    });
    jest.spyOn(baseCallbackHandler, 'default').mockImplementation(() => callbackHandler);
    const options: CallbackOptions = { redirectUri: '/foo' };
    const optionsProvider = jest.fn(() => options);
    const baseUrl = await setup(withoutApi);
    const { handleCallback, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      callback: handleCallback(optionsProvider)
    });
    await get(baseUrl, '/api/auth/callback');
    expect(optionsProvider).toHaveBeenCalled();
    expect(callbackHandler).toHaveBeenCalledWith(
      expect.any(IncomingMessage),
      expect.any(ServerResponse),
      expect.objectContaining(options)
    );
  });

  test('accept custom profile options provider', async () => {
    const afterRefetch = jest.fn(async (_req: IncomingMessage, _res: ServerResponse, session: Session) => session);
    const options: ProfileOptions = { refetch: true, afterRefetch };
    const optionsProvider = jest.fn(() => options);
    const baseUrl = await setup(withoutApi);
    const { handleProfile, handleAuth } = initAuth0(withoutApi);
    global.handleAuth = handleAuth.bind(null, {
      profile: handleProfile(optionsProvider)
    });
    const cookieJar = await login(baseUrl);
    await get(baseUrl, '/api/auth/me', { cookieJar });
    expect(optionsProvider).toHaveBeenCalled();
    expect(afterRefetch).toHaveBeenCalled();
  });
});
