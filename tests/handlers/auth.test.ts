import { IncomingMessage, ServerResponse } from 'http';
import { ArgumentsOf } from 'ts-jest';
import { withoutApi } from '../fixtures/default-settings';
import { setup, teardown } from '../fixtures/setup';
import { get } from '../auth0-session/fixtures/helpers';
import { initAuth0, OnError } from '../../src';

const handlerError = () =>
  expect.objectContaining({
    status: 400,
    code: 'ERR_CALLBACK_HANDLER_FAILURE'
  });

describe('auth handler', () => {
  afterEach(teardown);

  test('accept custom error handler', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.end());
    const baseUrl = await setup(withoutApi, { onError });
    await get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('use default error handler', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
    delete global.onError;
    jest.spyOn(console, 'error').mockImplementation(() => {});
    await expect(get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo')).rejects.toThrow(
      'Bad Request'
    );
    expect(console.error).toHaveBeenCalledWith(handlerError());
  });

  test('finish response if custom error does not', async () => {
    const onError = jest.fn();
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo', { fullResponse: true })
    ).rejects.toThrow('Internal Server Error');
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('finish response with custom error status', async () => {
    const onError = jest.fn<void, ArgumentsOf<OnError>>((_req, res) => res.status(418));
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth.bind(null, { onError });
    await expect(
      get(baseUrl, '/api/auth/callback?error=foo&error_description=bar&state=foo', { fullResponse: true })
    ).rejects.toThrow("I'm a Teapot");
    expect(onError).toHaveBeenCalledWith(expect.any(IncomingMessage), expect.any(ServerResponse), handlerError());
  });

  test('return 500 for unexpected error', async () => {
    const baseUrl = await setup(withoutApi);
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
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
    global.handleAuth = (await initAuth0(withoutApi)).handleAuth;
    await expect(get(baseUrl, '/api/auth/foo')).rejects.toThrow('Not Found');
  });
});
