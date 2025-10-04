import React from 'react';
import { render, screen } from '@testing-library/react';

import Index from '../../app/page';

// Mock the useUser hook
jest.mock('@auth0/nextjs-auth0/client', () => ({
  useUser: () => ({
    user: null,
    isLoading: false,
  }),
}));

describe('index', () => {
  it('should render without crashing', async () => {
    render(<Index />);

    expect(screen.getByTestId('hero')).toBeInTheDocument();
    expect(screen.getByText('DPoP (Demonstration of Proof-of-Possession) Example')).toBeInTheDocument();
  });
});
