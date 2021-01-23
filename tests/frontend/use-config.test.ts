import { renderHook } from '@testing-library/react-hooks';

import { withConfigProvider } from '../fixtures/frontend';
import { useConfig } from '../../src/frontend/use-config';

jest.mock('next/router', () => ({
  useRouter: (): any => ({ asPath: '/' })
}));

describe('context wrapper', () => {
  test('should provide the default login url', async () => {
    const { result } = renderHook(() => useConfig(), {
      wrapper: withConfigProvider({ loginUrl: '/api/auth/login' })
    });

    expect(result.current.loginUrl).toEqual('/api/auth/login');
  });

  test('should provide a custom login url', async () => {
    const { result } = renderHook(() => useConfig(), {
      wrapper: withConfigProvider({ loginUrl: '/api/custom-url' })
    });

    expect(result.current.loginUrl).toEqual('/api/custom-url');
  });

  test('should provide a custom returnTo url', async () => {
    const { result } = renderHook(() => useConfig(), {
      wrapper: withConfigProvider({ returnTo: '/foo' })
    });

    expect(result.current.returnTo).toEqual('/foo');
  });

  test('should provide a custom login url from an environment variable', async () => {
    process.env.NEXT_PUBLIC_AUTH0_LOGIN = '/api/custom-url';
    const { result } = renderHook(() => useConfig(), {
      wrapper: withConfigProvider()
    });

    expect(result.current.loginUrl).toEqual('/api/custom-url');
    delete process.env.NEXT_PUBLIC_AUTH0_LOGIN;
  });

  test('should provide a custom returnTo url from an environment variable', async () => {
    process.env.NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT = '/foo';
    const { result } = renderHook(() => useConfig(), {
      wrapper: withConfigProvider()
    });

    expect(result.current.returnTo).toEqual('/foo');
    delete process.env.NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT;
  });
});
