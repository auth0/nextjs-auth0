/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import { getResponse } from '../fixtures/app-router-helpers';

describe('auth handler (app router)', () => {
  test('return 500 for unexpected error', async () => {
    await expect(
      getResponse({
        url: '/api/auth/foo',
        extraHandlers: {
          foo: () => {
            throw new Error();
          }
        }
      })
    ).resolves.toMatchObject({ status: 500 });
  });

  test('return 404 for unknown routes', async () => {
    await expect(getResponse({ url: '/api/auth/foo' })).resolves.toMatchObject({ status: 404 });
  });

  test('return 404 for unknown routes including builtin props', async () => {
    await expect(getResponse({ url: '/api/auth/__proto__' })).resolves.toMatchObject({ status: 404 });
  });

  test('return 404 when routes have extra parts', async () => {
    await expect(getResponse({ url: '/api/auth/me/foo.css' })).resolves.toMatchObject({ status: 404 });
  });

  test('use default error handler', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    await expect(
      getResponse({
        url: '/api/auth/foo',
        extraHandlers: { foo: jest.fn().mockRejectedValue(new Error()), onError: undefined }
      })
    ).resolves.toMatchObject({ status: 500 });
    expect(console.error).toHaveBeenCalledWith(expect.any(Error));
  });

  test('accept custom error handler', async () => {
    const onError = jest.fn();
    await expect(
      getResponse({
        url: '/api/auth/foo',
        extraHandlers: {
          foo: jest.fn().mockRejectedValue(new Error()),
          onError
        }
      })
    ).resolves.toMatchObject({ status: 500 });
    expect(onError).toHaveBeenCalledWith(expect.any(Request), expect.any(Error));
  });

  test('accept custom error handler response', async () => {
    const onError = jest.fn().mockReturnValue(new Response(null, { status: 418 }));
    await expect(
      getResponse({
        url: '/api/auth/foo',
        extraHandlers: {
          foo: jest.fn().mockRejectedValue(new Error()),
          onError
        }
      })
    ).resolves.toMatchObject({ status: 418 });
    expect(onError).toHaveBeenCalled();
  });
});
