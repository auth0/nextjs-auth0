import { renderHook } from '@testing-library/react-hooks';

import { useUser } from '../../src';
import {
  fetchUserMock,
  fetchUserUnsuccessfulMock,
  fetchUserErrorMock,
  withUserProvider,
  user
} from '../fixtures/frontend';

describe('context wrapper', () => {
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
    const fetchSpy = jest.fn();
    (global as any).fetch = fetchSpy;
    const { result, waitForValueToChange } = renderHook(() => useUser(), {
      wrapper: withUserProvider({ profileUrl: '/api/custom-url' })
    });

    await waitForValueToChange(() => result.current.isLoading);
    expect(fetchSpy).toHaveBeenCalledWith('/api/custom-url');
  });

  afterAll(() => {
    delete (global as any).fetch;
  });
});
