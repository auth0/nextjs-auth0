/**
 * @jest-environment jsdom
 */
import '@testing-library/jest-dom/extend-expect';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';

import { fetchUserUnsuccessfulMock, fetchUserErrorMock, withUserProvider, user } from '../fixtures/frontend';
import { withPageAuthRequired } from '../../src/frontend';

const routerMock = {
  push: jest.fn(),
  asPath: '/'
};

jest.mock('next/router', () => ({ useRouter: (): any => routerMock }));

describe('with-page-auth-required csr', () => {
  afterEach(() => delete (global as any).fetch);

  it('should block access to a CSR page when not authenticated', async () => {
    (global as any).fetch = fetchUserUnsuccessfulMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider() });
    await waitFor(() => expect(routerMock.push).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText('Private')).not.toBeInTheDocument());
  });

  it('should allow access to a CSR page when authenticated', async () => {
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUserProvider({ user }) });
    await waitFor(() => expect(routerMock.push).not.toHaveBeenCalled());
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
    await waitFor(() => expect(routerMock.push).toHaveBeenCalledWith(expect.stringContaining('?returnTo=/foo')));
  });
});
