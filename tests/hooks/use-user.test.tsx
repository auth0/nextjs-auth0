import { renderHook } from '@testing-library/react-hooks';

import { useUser } from '../../src';
import { fetchUserMock, fetchUserFailureMock, withUser, user } from '../helpers/hooks';

describe('context wrapper', () => {
  test('should use the initial user', async () => {
    (global as any).fetch = fetchUserMock;

    const { result } = renderHook(() => useUser(), { wrapper: withUser(user) });

    expect(result.current.user).toEqual(user);
    expect(result.current.loading).toEqual(false);
  });

  test('should fetch the user', async () => {
    (global as any).fetch = fetchUserMock;

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUser(null) });

    expect(result.current.user).toEqual(null);
    expect(result.current.loading).toEqual(true);

    await waitForValueToChange(() => result.current.loading);

    expect(result.current.user).toEqual(user);
    expect(result.current.loading).toEqual(false);
  });

  test('should fail to fetch the user', async () => {
    (global as any).fetch = fetchUserFailureMock;

    const { result, waitForValueToChange } = renderHook(() => useUser(), { wrapper: withUser(null) });

    expect(result.current.user).toEqual(null);
    expect(result.current.loading).toEqual(true);

    await waitForValueToChange(() => result.current.loading);

    expect(result.current.user).toEqual(null);
    expect(result.current.loading).toEqual(false);
  });

  afterAll(() => {
    (global as any).fetch = undefined;
  });
});
