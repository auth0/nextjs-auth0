/**
 * @jest-environment jsdom
 */
import '@testing-library/jest-dom/extend-expect';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';

import { fetchUserUnsuccessfulMock, fetchUserErrorMock, withUserProvider, user } from '../fixtures/frontend';
import { withPageAuthRequired } from '../../src/frontend';

const windowLocation = window.location;
const routerMock: {
  basePath?: string;
  asPath: string;
} = {
  basePath: undefined,
  asPath: '/'
};

jest.mock('next/router', () => ({ useRouter: (): any => routerMock }));

describe('with-page-auth-required csr', () => {
  beforeAll(() => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore window.location is non-optional
    delete window.location;
    window.location = { ...windowLocation, assign: jest.fn() };
  });
  afterEach(() => delete (global as any).fetch);
  afterAll(() => (window.location = windowLocation));

  it('should deny access to a CSR page when not authenticated', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText('Private')).not.toBeInTheDocument());
  });

  it('should allow access to a CSR page when authenticated', async () => {
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider({ user }) });
    await waitFor(() => expect(window.location.assign).not.toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText('Private')).toBeInTheDocument());
  });

  it('should show an empty element when redirecting', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    const { container } = render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it('should show a custom element when redirecting', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const OnRedirecting = (): JSX.Element => <>Redirecting</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { onRedirecting: OnRedirecting });

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(screen.getByText('Redirecting')).toBeInTheDocument());
  });

  it('should show an empty fallback in case of error', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    const { container } = render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it('should show a custom fallback in case of error', async () => {
    (global as any).fetch = fetchUserErrorMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const OnError = (): JSX.Element => <>Error</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { onError: OnError });

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(screen.getByText('Error')).toBeInTheDocument());
  });

  it('should accept a returnTo url', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { returnTo: '/foo' });

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith(expect.stringContaining('?returnTo=/foo')));
  });

  it('should use a custom login url', async () => {
    process.env.NEXT_PUBLIC_AUTH0_LOGIN = '/api/foo';
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith(expect.stringContaining('/api/foo')));
    delete process.env.NEXT_PUBLIC_AUTH0_LOGIN;
  });

  it('should prepend the basePath to the returnTo URL', async () => {
    const asPath = routerMock.asPath;
    const basePath = routerMock.basePath;
    routerMock.basePath = '/foo';
    routerMock.asPath = '/bar';
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledWith(expect.stringContaining('?returnTo=/foo/bar'))
    );
    routerMock.basePath = basePath;
    routerMock.asPath = asPath;
  });

  it('should preserve multiple query params in the returnTo URL', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { returnTo: '/foo?bar=baz&qux=quux' });

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalled();
    });
    const url = new URL((window.location.assign as jest.Mock).mock.calls[0][0], 'https://example.com');
    expect(url.searchParams.get('returnTo')).toEqual('/foo?bar=baz&qux=quux');
  });
});
