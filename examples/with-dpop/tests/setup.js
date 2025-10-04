import '@testing-library/jest-dom';
import { vi } from 'vitest';
import React from 'react';

afterEach(() => {
  vi.clearAllMocks();
  vi.resetModules();
});

vi.mock('next/navigation', () => ({
  usePathname: () => ''
}));

// Mock UserProvider to avoid React hook issues
vi.mock('@auth0/nextjs-auth0/client', () => ({
  UserProvider: ({ children }) => React.createElement('div', { 'data-testid': 'user-provider' }, children),
  Auth0Provider: ({ children }) => React.createElement('div', { 'data-testid': 'auth0-provider' }, children),
  useUser: () => ({
    user: { sub: 'bob', name: 'Test User', email: 'test@example.com' },
    error: null,
    isLoading: false
  })
}));

vi.mock('./../lib/auth0', () => {
  return {
    auth0: {
      getSession: () => ({
        user: {
          sub: 'bob'
        }
      }),
      getAccessToken: () => 'access_token',
    }
  };
});