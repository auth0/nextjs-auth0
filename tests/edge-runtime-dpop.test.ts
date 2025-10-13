import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';

/**
 * Edge Runtime DPoP Compatibility Tests
 * 
 * These tests validate that DPoP functionality works correctly in Edge Runtime
 * environments where Node.js crypto APIs are not available.
 */

describe('Edge Runtime DPoP Compatibility', () => {
  let originalGlobalThis: any;
  let originalNodeCrypto: any;

  beforeAll(async () => {
    // Save original global state
    originalGlobalThis = globalThis;
    
    // Mock Edge Runtime environment
    (globalThis as any).EdgeRuntime = 'edge-runtime';
    
    // Clear module cache to force re-evaluation with Edge Runtime
    delete require.cache[require.resolve('../src/utils/dpopUtils.ts')];
  });

  afterAll(() => {
    // Restore original state
    if (originalGlobalThis.EdgeRuntime === undefined) {
      delete (globalThis as any).EdgeRuntime;
    } else {
      (globalThis as any).EdgeRuntime = originalGlobalThis.EdgeRuntime;
    }
  });

  it('should detect Edge Runtime environment correctly', async () => {
    // Should detect Edge Runtime
    expect(typeof (globalThis as any).EdgeRuntime).toBe('string');
  });

  it('should skip key pair validation in Edge Runtime', async () => {
    const { validateKeyPairCompatibility } = await import('../src/utils/dpopUtils');
    
    // Mock key objects
    const mockPrivateKey = { type: 'private' };
    const mockPublicKey = { type: 'public' };
    
    // Should return true (skip validation) in Edge Runtime
    const result = validateKeyPairCompatibility(mockPrivateKey, mockPublicKey);
    expect(result).toBe(true);
  });

  it('should handle DPoP configuration gracefully in Edge Runtime', async () => {
    const { validateDpopConfiguration } = await import('../src/utils/dpopUtils');
    
    // Mock environment variables
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      AUTH0_DPOP_PRIVATE_KEY: 'mock-private-key',
      AUTH0_DPOP_PUBLIC_KEY: 'mock-public-key'
    };

    const config = validateDpopConfiguration({
      useDpop: true,
      dpopOptions: {
        clockTolerance: 60
      }
    });

    // Should disable DPoP in Edge Runtime when using env vars
    expect(config.dpopKeyPair).toBeUndefined();
    expect(config.dpopOptions).toBeUndefined();

    // Restore environment
    process.env = originalEnv;
  });

  it('should work with pre-provided keypair in Edge Runtime', async () => {
    const { validateDpopConfiguration } = await import('../src/utils/dpopUtils');
    
    // Mock CryptoKey objects (what oauth4webapi uses)
    const mockKeyPair = {
      privateKey: {
        algorithm: { name: 'ECDSA' },
        extractable: false,
        type: 'private' as const,
        usages: ['sign' as const]
      } as CryptoKey,
      publicKey: {
        algorithm: { name: 'ECDSA' },
        extractable: false,
        type: 'public' as const,
        usages: ['verify' as const]
      } as CryptoKey
    };

    const config = validateDpopConfiguration({
      useDpop: true,
      dpopKeyPair: mockKeyPair,
      dpopOptions: {
        clockTolerance: 60
      }
    });

    // Should work with pre-provided keypair
    expect(config.dpopKeyPair).toEqual(mockKeyPair);
    expect(config.dpopOptions).toBeDefined();
    expect(config.dpopOptions?.clockTolerance).toBe(60);
  });

  it('should log appropriate warnings for Edge Runtime limitations', async () => {
    const { validateDpopConfiguration } = await import('../src/utils/dpopUtils');
    
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    
    // Mock environment variables
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      AUTH0_DPOP_PRIVATE_KEY: 'mock-private-key',
      AUTH0_DPOP_PUBLIC_KEY: 'mock-public-key'
    };

    validateDpopConfiguration({
      useDpop: true
    });

    // Should warn about Edge Runtime limitations
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Running in Edge Runtime environment')
    );

    consoleSpy.mockRestore();
    process.env = originalEnv;
  });
});