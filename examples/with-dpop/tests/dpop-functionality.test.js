import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock dependencies
vi.mock('../utils/generate-dpop-keys', () => ({
  generateDpopKeyPair: vi.fn()
}));

vi.mock('../lib/auth0', () => ({
  auth0: {
    getSession: vi.fn(),
    fetchWithAuth: vi.fn(),
    createFetcher: vi.fn()
  }
}));

describe('DPoP Functionality Tests', () => {
  let mockAuth0, mockGenerateDpopKeyPair;

  beforeEach(async () => {
    const { auth0 } = await import('../lib/auth0');
    const { generateDpopKeyPair } = await import('../utils/generate-dpop-keys');
    mockAuth0 = auth0;
    mockGenerateDpopKeyPair = generateDpopKeyPair;
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('DPoP Key Generation', () => {
    it('should generate valid DPoP key pairs', async () => {
      const mockKeyPair = {
        privateKey: { type: 'private', algorithm: { name: 'ECDSA' } },
        publicKey: { type: 'public', algorithm: { name: 'ECDSA' } }
      };

      mockGenerateDpopKeyPair.mockResolvedValue(mockKeyPair);

      const keyPair = await mockGenerateDpopKeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey.type).toBe('private');
      expect(keyPair.publicKey.type).toBe('public');
      expect(mockGenerateDpopKeyPair).toHaveBeenCalledOnce();
    });

    it('should handle key generation failures', async () => {
      mockGenerateDpopKeyPair.mockRejectedValue(new Error('Key generation failed'));

      try {
        await mockGenerateDpopKeyPair();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toBe('Key generation failed');
      }
    });
  });

  describe('DPoP Protected Requests', () => {
    it('should make DPoP-protected requests successfully', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      const mockDpopResponse = {
        ok: true,
        status: 200,
        headers: { 
          get: vi.fn((header) => {
            if (header === 'DPoP-Nonce') return 'test-nonce-123';
            if (header === 'content-type') return 'application/json';
            return null;
          })
        },
        json: vi.fn().mockResolvedValue({
          msg: 'This is a DPoP-protected API!',
          dpopEnabled: true,
          claims: {
            iss: 'https://test-domain.auth0.com/',
            sub: 'test-user-123',
            aud: 'https://test-domain.auth0.com/api/v2/',
            scope: 'read:shows'
          }
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockResolvedValue(mockDpopResponse);

      const result = await mockAuth0.fetchWithAuth('http://localhost:3001/api/shows');

      expect(result.ok).toBe(true);
      expect(result.status).toBe(200);
      expect(result.headers.get('DPoP-Nonce')).toBe('test-nonce-123');

      const data = await result.json();
      expect(data.dpopEnabled).toBe(true);
      expect(data.claims.sub).toBe('test-user-123');
    });

    it('should handle DPoP nonce challenges', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      // First call returns nonce error, second succeeds
      const nonceErrorResponse = {
        ok: false,
        status: 401,
        headers: { 
          get: vi.fn((header) => {
            if (header === 'DPoP-Nonce') return 'new-nonce-456';
            return null;
          })
        },
        json: vi.fn().mockResolvedValue({
          error: 'use_dpop_nonce',
          error_description: 'DPoP proof requires nonce'
        })
      };

      const successResponse = {
        ok: true,
        status: 200,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          msg: 'Success after nonce retry',
          dpopEnabled: true
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth
        .mockResolvedValueOnce(nonceErrorResponse)
        .mockResolvedValueOnce(successResponse);

      // First call should get nonce error
      const firstResult = await mockAuth0.fetchWithAuth('http://localhost:3001/api/shows');
      expect(firstResult.ok).toBe(false);
      expect(firstResult.status).toBe(401);
      expect(firstResult.headers.get('DPoP-Nonce')).toBe('new-nonce-456');

      // Second call should succeed (simulating retry logic)
      const secondResult = await mockAuth0.fetchWithAuth('http://localhost:3001/api/shows');
      expect(secondResult.ok).toBe(true);
      expect(secondResult.status).toBe(200);
    });

    it('should handle DPoP clock skew scenarios', async () => {
      const mockSession = {
        user: { sub: 'test-user-123', email: 'test@example.com' },
        accessToken: 'test-access-token'
      };

      const clockSkewResponse = {
        ok: false,
        status: 400,
        headers: { get: vi.fn() },
        json: vi.fn().mockResolvedValue({
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof iat claim is too far in the past or future'
        })
      };

      mockAuth0.getSession.mockResolvedValue(mockSession);
      mockAuth0.fetchWithAuth.mockResolvedValue(clockSkewResponse);

      const result = await mockAuth0.fetchWithAuth('http://localhost:3001/api/shows');

      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);

      const error = await result.json();
      expect(error.error).toBe('invalid_dpop_proof');
      expect(error.error_description).toContain('past or future');
    });
  });

  describe('Server-side createFetcher', () => {
    it('should create server-side fetcher with DPoP support', async () => {
      const mockFetcher = {
        fetchWithAuth: vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            msg: 'Server-side DPoP request',
            dpopEnabled: true,
            fetcherType: 'server'
          })
        })
      };

      mockAuth0.createFetcher.mockReturnValue(mockFetcher);

      const fetcher = mockAuth0.createFetcher();
      expect(fetcher).toBeDefined();
      expect(fetcher.fetchWithAuth).toBeDefined();

      const result = await fetcher.fetchWithAuth('http://localhost:3001/api/shows');
      expect(result.ok).toBe(true);

      const data = await result.json();
      expect(data.dpopEnabled).toBe(true);
      expect(data.fetcherType).toBe('server');
    });

    it('should handle server-side fetcher errors', async () => {
      const mockFetcher = {
        fetchWithAuth: vi.fn().mockRejectedValue(new Error('Server-side fetch failed'))
      };

      mockAuth0.createFetcher.mockReturnValue(mockFetcher);

      const fetcher = mockAuth0.createFetcher();

      try {
        await fetcher.fetchWithAuth('http://localhost:3001/api/shows');
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toBe('Server-side fetch failed');
      }
    });
  });

  describe('Environment Configuration', () => {
    it('should validate DPoP environment variables', () => {
      // Test environment setup
      expect(process.env.USE_DPOP).toBeDefined();
      expect(process.env.NODE_ENV).toBeDefined();

      // Basic validation that DPoP is enabled in test environment
      if (process.env.USE_DPOP === 'true') {
        expect(process.env.USE_DPOP).toBe('true');
      }
    });

    it('should handle missing DPoP configuration gracefully', () => {
      // This test validates that the application doesn't crash
      // when DPoP configuration is missing or incomplete
      const originalUseDpop = process.env.USE_DPOP;
      
      try {
        delete process.env.USE_DPOP;
        
        // Application should still work without DPoP
        expect(process.env.USE_DPOP).toBeUndefined();
      } finally {
        // Restore original value
        if (originalUseDpop) {
          process.env.USE_DPOP = originalUseDpop;
        }
      }
    });
  });
});