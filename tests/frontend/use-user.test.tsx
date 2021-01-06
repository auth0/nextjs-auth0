import { renderHook } from '@testing-library/react-hooks';

import { useUser } from '../../src';
import { fetchUserMock, fetchUserFailureMock, withUser, user } from '../fixtures/frontend';

describe('context wrapper', () => {
  test('should use the initial user', async () => {
    const { result } = renderHook(() => useUser(), { wrapper: withUser(user) });

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should fetch the user', async () => {
    (global as any).fetch = fetchUserMock;

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUser() });

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(user);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(false);
  });

  test('should fail to fetch the user', async () => {
    (global as any).fetch = fetchUserFailureMock;

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUser() });

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(undefined);
    expect(result.current.isLoading).toEqual(true);

    await waitForValueToChange(() => result.current.isLoading);

    expect(result.current.user).toEqual(undefined);
    expect(result.current.error).toEqual(new Error('The request to /api/auth/me failed'));
    expect(result.current.isLoading).toEqual(false);
  });

  afterAll(() => {
    delete (global as any).fetch;
  });
});
