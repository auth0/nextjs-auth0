import { renderHook, act } from '@testing-library/react-hooks';

import {
  fetchUserMock,
  fetchUserUnsuccessfulMock,
  fetchUserErrorMock,
  withUserProvider,
  user
} from '../fixtures/frontend';
import { useConfig } from '../../src/frontend';
import { useUser, UserContext } from '../../src';
import React from 'react';

describe('context wrapper', () => {
  afterEach(() => delete (global as any).fetch);

  test('should fetch the user', async () => {
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

  test('should discard the response when the status code is not successful', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should fail to fetch the user', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toEqual(new Error('The request to /api/auth/me failed'));
    expect(result.current.isLoading).toEqual(false);
  });

  test('should provide the existing user', async () => {
    const { result } = renderHook(() => useUser(), { wrapper: withUserProvider({ user }) });

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

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

  test('should check the session when logged in', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toBeUndefined();

    (global as any).fetch = fetchUserMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should check the session when logged out', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toEqual(user);

    (global as any).fetch = fetchUserUnsuccessfulMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toEqual(false);
  });

  test('should throw an error when not wrapped in UserProvider', async () => {
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

  test('should use the override fetch behaviour', async () => {
    const fetchSpy = jest.fn();
    (global as any).fetch = fetchSpy;

    const returnValue = 'foo';
    const customFetcher = jest.fn().mockReturnValue(Promise.resolve(returnValue));

    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider({ fetcher: customFetcher })
    });

    await waitForValueToChange(() => result.current.isLoading);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(customFetcher).toHaveBeenCalledWith('/api/auth/me');
    expect(result.current.user).toBe(returnValue);
  });
});
