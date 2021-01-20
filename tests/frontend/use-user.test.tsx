import { renderHook, act } from '@testing-library/react-hooks';

import {
  fetchUserMock,
  fetchUserUnsuccessfulMock,
  fetchUserErrorMock,
  withUserProvider,
  user
} from '../fixtures/frontend';
import { useUser } from '../../src';

describe('context wrapper', () => {
  afterEach(() => delete (global as any).fetch);

  test('should fetch the user', async () => {
    (global as any).fetch = fetchUserMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should discard the response when the status code is not successful', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should fail to fetch the user', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(new Error('The request to /api/auth/me failed'));
    expect(result.current.isLoading).toEqual(false);
  });

  test('should use the existing user', async () => {
    const { result } = renderHook(() => useUser(), { wrapper: withUserProvider({ user }) });

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should use a custom profileUrl', async () => {
    const fetchSpy = jest.fn().mockReturnValue({ then: () => Promise.resolve() });
    (global as any).fetch = fetchSpy;
    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider({ profileUrl: '/api/custom-url' })
    });

    await waitForValueToChange(() => result.current.isLoading);
    expect(fetchSpy).toHaveBeenCalledWith('/api/custom-url');
  });

  test('should check the session when logged in', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUserProvider() });

    await waitForValueToChange(() => result.current.isLoading);
    expect(result.current.user).toBeUndefined;

    (global as any).fetch = fetchUserMock;

    await act(async () => await result.current.checkSession());
    expect(result.current.user).toEqual(user);
    expect(result.current.error).toEqual(undefined);
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
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });
});
