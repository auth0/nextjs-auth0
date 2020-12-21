/**
 * @jest-environment jsdom
 */
import '@testing-library/jest-dom/extend-expect';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';

import { fetchUserFailureMock, withUser, user } from '../fixtures/frontend';
import { withCSRAuthRequired } from '../../src/frontend';

const routerMock = {
  push: jest.fn(),
  asPath: '/'
};

jest.mock('next/router', () => ({ useRouter: (): any => routerMock }));

describe('with-csr-auth-required', () => {
  it('should block access to a CSR page when not authenticated', async () => {
    (global as any).fetch = fetchUserFailureMock;
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withCSRAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUser() });
    await waitFor(() => expect(routerMock.push).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByText('Private')).not.toBeInTheDocument());
  });

  it('should allow access to a CSR page when authenticated', async () => {
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withCSRAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withUser(user) });
    await waitFor(() => expect(routerMock.push).not.toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText('Private')).toBeInTheDocument());
  });

  it('should show a custom redirecting message', async () => {
    const MyPage = (): JSX.Element => <>Private</>;
    const OnRedirecting = (): JSX.Element => <>Redirecting</>;
    const ProtectedPage = withCSRAuthRequired(MyPage, { onRedirecting: OnRedirecting });

    render(<ProtectedPage />, { wrapper: withUser() });
    await waitFor(() => expect(screen.getByText('Redirecting')).toBeInTheDocument());
  });

  it('should accept a returnTo url', async () => {
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withCSRAuthRequired(MyPage, { returnTo: '/foo' });

    render(<ProtectedPage />, { wrapper: withUser() });
    await waitFor(() => expect(routerMock.push).toHaveBeenCalledWith(expect.stringContaining('?returnTo=/foo')));
  });

  afterAll(() => {
    delete (global as any).fetch;
  });
});
