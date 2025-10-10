import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the dependencies first
vi.mock('../lib/auth0', () => ({
  auth0: {
    getSession: vi.fn(),
    getAccessToken: vi.fn(),
    fetchWithAuth: vi.fn(),
    createFetcher: vi.fn(() => ({
      fetchWithAuth: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          msg: 'This is a DPoP-protected API!',
          dpopEnabled: true,
          claims: {
            iss: 'https://test-domain.auth0.com/',
            sub: 'test-user-123',
            aud: 'https://test-domain.auth0.com/api/v2/',
            scope: 'read:shows',
            iat: Math.floor(Date.now() / 1000) - 300,
            exp: Math.floor(Date.now() / 1000) + 3600
          }
        })
      })
    }))
  }
}));

// Import after mocking
const { GET } = await import('../app/api/shows/route.js');
const { auth0 } = await import('../lib/auth0');

describe('/api/shows route - Server-side only', () => {
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
    
    auth0.getSession.mockResolvedValue(mockSession);

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.msg).toBe('This is a DPoP-protected API!');
    expect(data.dpopEnabled).toBe(true);
    expect(data.claims).toBeDefined();
    expect(data.claims.sub).toBe('test-user-123');
  });
});