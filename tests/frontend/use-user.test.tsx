import { renderHook, act } from '@testing-library/react-hooks';

import {
  fetchUserMock,
  fetchUserErrorMock,
  fetchUserNetworkErrorMock,
  fetchUserUnauthorizedMock,
  withUserProvider,
  user
} from '../fixtures/frontend';
import { useUser, UserContext, RequestError } from '../../src/client';
import { useConfig } from '../../src/client/use-config';
import React from 'react';

describe('context wrapper', () => {
  afterEach(() => delete (global as any).fetch);

  test('should use the default profile url', async () => {
    const fetchSpy = jest.fn().mockReturnValue(Promise.resolve());
    (global as any).fetch = fetchSpy;
    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider()
    });

    await waitForValueToChange(() => result.current.isLoading);
    expect(fetchSpy).toHaveBeenCalledWith('/api/auth/me');
  });

  test('should accept a custom profile url', async () => {
    const fetchSpy = jest.fn().mockReturnValue(Promise.resolve());
    (global as any).fetch = fetchSpy;
    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider({ profileUrl: '/api/custom-url' })
    });

    await waitForValueToChange(() => result.current.isLoading);
    expect(fetchSpy).toHaveBeenCalledWith('/api/custom-url');
  });

  test('should use a custom profile url from an environment variable', async () => {
    process.env.NEXT_PUBLIC_AUTH0_PROFILE = '/api/custom-url';
    const fetchSpy = jest.fn().mockReturnValue(Promise.resolve());
    (global as any).fetch = fetchSpy;
    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider()
    });

    await waitForValueToChange(() => result.current.isLoading);
    expect(fetchSpy).toHaveBeenCalledWith('/api/custom-url');
    delete process.env.NEXT_PUBLIC_AUTH0_PROFILE;
  });

  test('should accept a custom login url', async () => {
    const { result } = renderHook(() => useConfig(), {
      wrapper: withUserProvider({ user, loginUrl: '/api/custom-url' })
    });

    expect(result.current.loginUrl).toEqual('/api/custom-url');
  });

  test('should accept a custom fetcher', async () => {
    const fetchSpy = jest.fn();
    (global as any).fetch = fetchSpy;

    const returnValue = 'foo';
    const customFetcher = jest.fn().mockResolvedValue(returnValue);

    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider({ fetcher: customFetcher })
    });

    await waitForValueToChange(() => result.current.isLoading);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(customFetcher).toHaveBeenCalledWith('/api/auth/me');
    expect(result.current.user).toBe(returnValue);
  });
});

describe('user provider', () => {
  test('should throw an error when the app is not wrapped in UserProvider', async () => {
    const expectedError = 'You forgot to wrap your app in <UserProvider>';
    const { result } = renderHook(() => useUser());

    expect(() => result.current.user).toThrowError(expectedError);
    expect(() => result.current.error).toThrowError(expectedError);
    expect(() => result.current.isLoading).toThrowError(expectedError);
    expect(result.current.checkSession).toThrowError(expectedError);
  });

  test('should be able to stub UserProvider with UserContext.Provider', async () => {
    const { result } = renderHook(() => useUser(), {
      wrapper: (props: any): React.ReactElement => <UserContext.Provider {...props} value={{ user: { foo: 'bar' } }} />
    });

    expect(result.current.user).toEqual({ foo: 'bar' });
  });
});

describe('hook', () => {
  afterEach(() => delete (global as any).fetch);

  test('should provide the fetched user', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide the existing user', async () => {
    const { result } = renderHook(() => useUser(), { wrapper: withUserProvider({ user }) });

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide no user when the status code is 204', async () => {
    (global as any).fetch = fetchUserUnauthorizedMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide an error when the request fails', async () => {
    (global as any).fetch = fetchUserNetworkErrorMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeInstanceOf(RequestError);
    expect((result.current.error as RequestError).status).toEqual(0);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide an error when the status code is not successful', async () => {
    const status = 400;
    (global as any).fetch = () => Promise.resolve({ ok: false, status });

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeInstanceOf(RequestError);
    expect((result.current.error as RequestError).status).toEqual(status);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide an error when a custom fetcher throws an error', async () => {
    const error = new Error();
    const fetcher = jest.fn().mockRejectedValue(error);

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider({ fetcher }) });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toEqual(error);
    expect(result.current.isLoading).toEqual(false);
  });
});

describe('check session', () => {
  afterEach(() => delete (global as any).fetch);

  test('should set the user after logging in', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toBeUndefined();

    (global as any).fetch = fetchUserMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should not unset the user due to a network error while logged in', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toEqual(user);

    (global as any).fetch = fetchUserNetworkErrorMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeDefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should not unset the user due to an error response while logged in', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toEqual(user);

    (global as any).fetch = fetchUserErrorMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeDefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should not unset the user due to the custom fetcher throwing an error while logged in', async () => {
    (global as any).fetch = fetchUserMock;
    const fetcher = jest.fn().mockResolvedValueOnce(user).mockRejectedValueOnce(new Error());

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider({ fetcher }) });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toEqual(user);

    (global as any).fetch = fetchUserErrorMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeDefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should unset the user after logging out', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toEqual(user);

    (global as any).fetch = fetchUserUnauthorizedMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });
});

describe('re-renders', () => {
  afterEach(() => delete (global as any).fetch);

  test('should not update context value after rerender with no state change', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const { waitForNextUpdate, result, rerender } = renderHook(() => useUser(), {
      wrapper: withUserProvider()
    });

    await waitForNextUpdate();
    const memoized = result.current;

    rerender();

    expect(result.current).toBe(memoized);
  });
});
