import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

// Mock the client-side fetchWithAuth first
vi.mock('@auth0/nextjs-auth0/client', () => ({
  UserProvider: ({ children }) => children,
  useUser: () => ({ 
    user: { sub: 'test-user-123', email: 'test@example.com' },
    isLoading: false 
  }),
  fetchWithAuth: vi.fn()
}));

// Mock fetch for server-side API calls
global.fetch = vi.fn();

// Import component after mocking
const HomePage = await import('../app/page.jsx');
const { fetchWithAuth, UserProvider } = await import('@auth0/nextjs-auth0/client');

describe('Dual DPoP Testing Pattern', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return identical results from both server-side and client-side testing approaches', async () => {
    const mockApiResponse = {
      msg: 'This is a DPoP-protected API!',
      dpopEnabled: true,
      claims: {
        iss: 'https://test-domain.auth0.com/',
        sub: 'test-user-123',
        aud: 'https://test-domain.auth0.com/api/v2/',
        scope: 'openid profile email',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      }
    };

    // Mock server-side API route response
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockApiResponse)
    });

    // Mock client-side fetchWithAuth response
    fetchWithAuth.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockApiResponse)
    });

    render(
      <UserProvider>
        <HomePage.default />
      </UserProvider>
    );

    // Test server-side approach
    const serverButton = screen.getByText('Test Server-Side DPoP API');
    fireEvent.click(serverButton);

    await waitFor(() => {
      expect(screen.getByText('✅ Server-Side DPoP API Test Successful!')).toBeInTheDocument();
    });

    // Get server-side results
    const serverResults = await waitFor(() => 
      screen.getByTestId('api-response')
    );

    // Test client-side approach
    const clientButton = screen.getByText('Test Client-Side DPoP API');
    fireEvent.click(clientButton);

    await waitFor(() => {
      expect(screen.getByText('✅ Client-Side DPoP API Test Successful!')).toBeInTheDocument();
    });

    // Get client-side results
    const clientResults = await waitFor(() =>
      screen.getByTestId('client-api-response')
    );

    // Verify both approaches were called correctly
    expect(global.fetch).toHaveBeenCalledWith('/api/shows');
    expect(fetchWithAuth).toHaveBeenCalledWith(`http://localhost:${process.env.API_PORT || '3001'}/api/shows`);

    // Verify results contain the same essential data
    expect(serverResults.textContent).toContain('This is a DPoP-protected API!');
    expect(clientResults.textContent).toContain('This is a DPoP-protected API!');
    expect(serverResults.textContent).toContain('test-user-123');
    expect(clientResults.textContent).toContain('test-user-123');
  });

  it('should handle errors identically in both testing approaches', async () => {
    const errorMessage = 'API request failed';

    // Mock server-side API route error
    global.fetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({ error: errorMessage })
    });

    // Mock client-side fetchWithAuth error
    fetchWithAuth.mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({ error: errorMessage })
    });

    render(
      <UserProvider>
        <HomePage.default />
      </UserProvider>
    );

    // Test server-side error handling
    const serverButton = screen.getByText('Test Server-Side DPoP API');
    fireEvent.click(serverButton);

    await waitFor(() => {
      expect(screen.getByText('❌ Server-Side DPoP API Test Failed')).toBeInTheDocument();
    });

    // Test client-side error handling
    const clientButton = screen.getByText('Test Client-Side DPoP API');
    fireEvent.click(clientButton);

    await waitFor(() => {
      expect(screen.getByText('❌ Client-Side DPoP API Test Failed')).toBeInTheDocument();
    });

    // Verify both show error states
    const serverResults = screen.getByTestId('api-error');
    const clientResults = screen.getByTestId('client-api-error');

    expect(serverResults.textContent).toContain(errorMessage);
    expect(clientResults.textContent).toContain(errorMessage);
  });

  it('should validate response structure consistency between approaches', async () => {
    const mockResponse = {
      msg: 'This is a DPoP-protected API!',
      dpopEnabled: true,
      claims: {
        iss: 'https://test-domain.auth0.com/',
        sub: 'test-user-123'
      }
    };

    // Both approaches return the same structure
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse)
    });

    fetchWithAuth.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse)
    });

    render(
      <UserProvider>
        <HomePage.default />
      </UserProvider>
    );

    // Trigger both tests
    fireEvent.click(screen.getByText('Test Server-Side DPoP API'));
    fireEvent.click(screen.getByText('Test Client-Side DPoP API'));

    await waitFor(() => {
      expect(screen.getByTestId('api-response')).toBeInTheDocument();
      expect(screen.getByTestId('client-api-response')).toBeInTheDocument();
    });

    // Verify both results have identical structure elements
    const serverResults = screen.getByTestId('api-response');
    const clientResults = screen.getByTestId('client-api-response');

    // Both should show the message
    expect(serverResults.textContent).toContain(mockResponse.msg);
    expect(clientResults.textContent).toContain(mockResponse.msg);

    // Both should show DPoP status
    expect(serverResults.textContent).toContain('DPoP Enabled: Yes');
    expect(clientResults.textContent).toContain('DPoP Enabled: Yes');

    // Both should show claims
    expect(serverResults.textContent).toContain(mockResponse.claims.sub);
    expect(clientResults.textContent).toContain(mockResponse.claims.sub);
  });
});
