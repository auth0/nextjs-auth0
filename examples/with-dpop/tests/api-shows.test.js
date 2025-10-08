import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the dependencies first
vi.mock('../lib/auth0', () => ({
  auth0: {
    getSession: vi.fn(),
    getAccessToken: vi.fn(),
    fetchWithAuth: vi.fn()
  }
}));

// Import after mocking
const { GET } = await import('../app/api/shows/route.js');
const { auth0 } = await import('../lib/auth0');

describe('/api/shows route', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.API_PORT = '3001';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return 401 when no session exists', async () => {
    auth0.getSession.mockResolvedValue(null);

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('Not authenticated');
    expect(auth0.getSession).toHaveBeenCalledOnce();
  });

  it('should successfully process DPoP API request with valid session', async () => {
    const mockSession = {
      user: { sub: 'test-user-123', email: 'test@example.com' }
    };
    
    const mockAccessToken = 'mock-access-token-12345';
    
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

    // Setup mocks
    auth0.getSession.mockResolvedValue(mockSession);
    auth0.getAccessToken.mockResolvedValue({ token: mockAccessToken });
    auth0.fetchWithAuth.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get: vi.fn().mockReturnValue('application/json')
      },
      json: vi.fn().mockResolvedValue(mockApiResponse)
    });

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.msg).toBe('This is a DPoP-protected API!');
    expect(data.dpopEnabled).toBe(true);
    expect(data.claims).toBeDefined();
    expect(data.claims.sub).toBe('test-user-123');

        // Verify Auth0 interactions
    expect(auth0.getSession).toHaveBeenCalledTimes(2);
    // getAccessToken is called once by ServerFetcher's fetchWithAuth delegation
    expect(auth0.getAccessToken).toHaveBeenCalledTimes(1);
    
    // With ServerFetcher, fetchWithAuth receives a Request object with the resolved URL
    expect(auth0.fetchWithAuth).toHaveBeenCalledOnce();
    const fetchCall = auth0.fetchWithAuth.mock.calls[0];
    const requestArg = fetchCall[0];
    expect(requestArg).toBeInstanceOf(Request);
    expect(requestArg.url).toBe('http://localhost:3001/api/shows');
  });

  it('should handle API server errors gracefully', async () => {
    const mockSession = {
      user: { sub: 'test-user-123', email: 'test@example.com' }
    };
    
    const mockAccessToken = 'mock-access-token-12345';

    // Setup mocks for error scenario
    auth0.getSession.mockResolvedValue(mockSession);
    auth0.getAccessToken.mockResolvedValue({ token: mockAccessToken });
    auth0.fetchWithAuth.mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      headers: {
        get: vi.fn().mockReturnValue('application/json')
      },
      text: vi.fn().mockResolvedValue('{"error": "API server error"}'),
      json: vi.fn().mockResolvedValue({ error: 'API server error' })
    });

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(500);
    expect(data.error).toBe('API request failed');
  });

  it('should handle network errors and exceptions', async () => {
    const mockSession = {
      user: { sub: 'test-user-123', email: 'test@example.com' }
    };

    auth0.getSession.mockResolvedValue(mockSession);
    auth0.getAccessToken.mockRejectedValue(new Error('Token retrieval failed'));

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(500);
    expect(data.error).toBe('Token retrieval failed');
    expect(data.errorType).toBe('Error');
    expect(data.timestamp).toBeDefined();
  });

  it('should use correct API port from environment', async () => {
    process.env.API_PORT = '4001';
    
    const mockSession = { user: { sub: 'test-user' } };
    auth0.getSession.mockResolvedValue(mockSession);
    auth0.getAccessToken.mockResolvedValue({ token: 'token' });
    auth0.fetchWithAuth.mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: vi.fn() },
      json: vi.fn().mockResolvedValue({ msg: 'success' })
    });

    await GET();

    // With ServerFetcher, fetchWithAuth receives a Request object with the resolved URL
    expect(auth0.fetchWithAuth).toHaveBeenCalledOnce();
    const fetchCall = auth0.fetchWithAuth.mock.calls[0];
    const requestArg = fetchCall[0];
    expect(requestArg).toBeInstanceOf(Request);
    expect(requestArg.url).toBe('http://localhost:4001/api/shows');
  });

  it('should default to port 3001 when API_PORT is not set', async () => {
    delete process.env.API_PORT;
    
    const mockSession = { user: { sub: 'test-user' } };
    auth0.getSession.mockResolvedValue(mockSession);
    auth0.getAccessToken.mockResolvedValue({ token: 'token' });
    auth0.fetchWithAuth.mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: vi.fn() },
      json: vi.fn().mockResolvedValue({ msg: 'success' })
    });

    await GET();

    // With ServerFetcher, fetchWithAuth receives a Request object with the resolved URL
    expect(auth0.fetchWithAuth).toHaveBeenCalledOnce();
    const fetchCall = auth0.fetchWithAuth.mock.calls[0];
    const requestArg = fetchCall[0];
    expect(requestArg).toBeInstanceOf(Request);
    expect(requestArg.url).toBe('http://localhost:3001/api/shows');
  });
});
