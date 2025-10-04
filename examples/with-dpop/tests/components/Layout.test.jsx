import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';

import { withAuth0Provider } from '../fixtures';
import Layout from '../../components/Layout';

describe('Layout', () => {
  it('should render without crashing', async () => {
    render(<Layout>Text</Layout>, { wrapper: withAuth0Provider({ user: undefined }) });

    await waitFor(() => expect(screen.getByTestId('layout')).toBeInTheDocument());
    expect(screen.getByTestId('navbar')).toBeInTheDocument();
    expect(screen.getByText('Text')).toBeInTheDocument();
  });
});
