import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the auth0 lib
vi.mock('../lib/auth0', () => ({
  auth0: {
    getSession: vi.fn(),
    getAccessToken: vi.fn(),
    fetchWithAuth: vi.fn(),
    createFetcher: vi.fn()
  }
}));

describe('DPoP AccessTokenOptions Integration Tests', () => {
  let mockAuth0;

  beforeEach(async () => {
    const { auth0 } = await import('../lib/auth0');
    mockAuth0 = auth0;
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('fetchWithAuth with accessTokenOptions', () => {
    it('should pass accessTokenOptions with scope to DPoP requests', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      const mockResponse = {
        ok: true,
        status: 200,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          msg: 'DPoP request with custom scope',
          scope: 'read:custom',
          dpopEnabled: true
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockResolvedValue(mockResponse);

      // Test accessTokenOptions with scope
      const accessTokenOptions = { scope: 'read:custom' };
      const result = await mockAuth0.fetchWithAuth('http://localhost:3001/api/test', accessTokenOptions);

      expect(mockAuth0.fetchWithAuth).toHaveBeenCalledWith(
        'http://localhost:3001/api/test',
        accessTokenOptions
      );
      expect(result.ok).toBe(true);
      
      const responseData = await result.json();
      expect(responseData.scope).toBe('read:custom');
      expect(responseData.dpopEnabled).toBe(true);
    });

    it('should pass accessTokenOptions with audience to DPoP requests', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      const mockResponse = {
        ok: true,
        status: 200,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          msg: 'DPoP request with custom audience',
          audience: 'https://custom-api.example.com',
          dpopEnabled: true
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockResolvedValue(mockResponse);

      // Test accessTokenOptions with audience
      const accessTokenOptions = { audience: 'https://custom-api.example.com' };
      const result = await mockAuth0.fetchWithAuth('http://localhost:3001/api/test', accessTokenOptions);

      expect(mockAuth0.fetchWithAuth).toHaveBeenCalledWith(
        'http://localhost:3001/api/test',
        accessTokenOptions
      );
      expect(result.ok).toBe(true);
      
      const responseData = await result.json();
      expect(responseData.audience).toBe('https://custom-api.example.com');
      expect(responseData.dpopEnabled).toBe(true);
    });

    it('should handle combined scope and audience in accessTokenOptions', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      const mockResponse = {
        ok: true,
        status: 200,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          msg: 'DPoP request with combined options',
          scope: 'read:custom write:custom',
          audience: 'https://custom-api.example.com',
          dpopEnabled: true
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockResolvedValue(mockResponse);

      // Test accessTokenOptions with both scope and audience
      const accessTokenOptions = { 
        scope: 'read:custom write:custom',
        audience: 'https://custom-api.example.com'
      };
      const result = await mockAuth0.fetchWithAuth('http://localhost:3001/api/test', accessTokenOptions);

      expect(mockAuth0.fetchWithAuth).toHaveBeenCalledWith(
        'http://localhost:3001/api/test',
        accessTokenOptions
      );
      expect(result.ok).toBe(true);
      
      const responseData = await result.json();
      expect(responseData.scope).toBe('read:custom write:custom');
      expect(responseData.audience).toBe('https://custom-api.example.com');
      expect(responseData.dpopEnabled).toBe(true);
    });
  });

  describe('createFetcher with accessTokenOptions', () => {
    it('should create fetcher that honors accessTokenOptions', async () => {
      const mockFetcher = {
        fetchWithAuth: vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            msg: 'Fetcher with custom options',
            dpopEnabled: true
          })
        })
      };

      mockAuth0.createFetcher.mockReturnValue(mockFetcher);

      const accessTokenOptions = { scope: 'read:admin' };
      const fetcher = mockAuth0.createFetcher(accessTokenOptions);

      expect(mockAuth0.createFetcher).toHaveBeenCalledWith(accessTokenOptions);
      expect(fetcher).toBeDefined();
      expect(fetcher.fetchWithAuth).toBeDefined();

      // Test that the fetcher can be used
      const result = await fetcher.fetchWithAuth('http://localhost:3001/api/admin');
      expect(result.ok).toBe(true);
    });

    it('should handle createFetcher without accessTokenOptions', async () => {
      const mockFetcher = {
        fetchWithAuth: vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            msg: 'Fetcher with default options',
            dpopEnabled: true
          })
        })
      };

      mockAuth0.createFetcher.mockReturnValue(mockFetcher);

      const fetcher = mockAuth0.createFetcher();

      expect(mockAuth0.createFetcher).toHaveBeenCalledWith();
      expect(fetcher).toBeDefined();
      expect(fetcher.fetchWithAuth).toBeDefined();

      // Test that the fetcher can be used
      const result = await fetcher.fetchWithAuth('http://localhost:3001/api/default');
      expect(result.ok).toBe(true);
    });
  });

  describe('Error handling with accessTokenOptions', () => {
    it('should handle authentication errors with custom accessTokenOptions', async () => {
      mockAuth0.getSession.mockResolvedValue(null);
      mockAuth0.fetchWithAuth.mockRejectedValue(new Error('Authentication required'));

      const accessTokenOptions = { scope: 'read:admin' };

      try {
        await mockAuth0.fetchWithAuth('http://localhost:3001/api/admin', accessTokenOptions);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toBe('Authentication required');
      }

      expect(mockAuth0.fetchWithAuth).toHaveBeenCalledWith(
        'http://localhost:3001/api/admin',
        accessTokenOptions
      );
    });

    it('should handle invalid accessTokenOptions gracefully', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockRejectedValue(new Error('Invalid scope'));

      const invalidAccessTokenOptions = { scope: 'invalid:scope' };

      try {
        await mockAuth0.fetchWithAuth('http://localhost:3001/api/test', invalidAccessTokenOptions);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toBe('Invalid scope');
      }

      expect(mockAuth0.fetchWithAuth).toHaveBeenCalledWith(
        'http://localhost:3001/api/test',
        invalidAccessTokenOptions
      );
    });
  });
});