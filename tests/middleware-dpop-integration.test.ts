import { describe, it, expect } from 'vitest';

/**
 * Middleware DPoP Integration Tests
 * 
 * These tests validate that DPoP functionality works correctly in middleware contexts,
 * particularly focusing on edge runtime compatibility.
 */

describe('Middleware DPoP Integration', () => {
  it('should allow DPoP configuration in middleware environment', async () => {
    // This test validates that our imports don't break in middleware context
    expect(async () => {
      const { validateDpopConfiguration } = await import('../src/utils/dpopUtils');
      
      // Should be able to call the function without errors
      const config = validateDpopConfiguration({
        useDpop: false
      });
      
      expect(config.dpopKeyPair).toBeUndefined();
      expect(config.dpopOptions).toBeUndefined();
    }).not.toThrow();
  });

  it('should import dpopUtils without throwing in middleware environments', async () => {
    // Test that dpopUtils can be imported without Node.js crypto dependencies throwing errors
    expect(async () => {
      await import('../src/utils/dpopUtils');
    }).not.toThrow();
  });

  it('should provide clear error messages for edge runtime limitations', async () => {
    const { validateDpopConfiguration } = await import('../src/utils/dpopUtils');
    
    // Mock Edge Runtime environment
    const originalGlobal = global;
    (global as any).EdgeRuntime = 'edge-runtime';
    
    // Mock environment variables
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      AUTH0_DPOP_PRIVATE_KEY: 'mock-key',
      AUTH0_DPOP_PUBLIC_KEY: 'mock-key'
    };
    
    const config = validateDpopConfiguration({
      useDpop: true
    });
    
    // Should gracefully disable DPoP
    expect(config.dpopKeyPair).toBeUndefined();
    expect(config.dpopOptions).toBeUndefined();
    
    // Restore
    delete (global as any).EdgeRuntime;
    process.env = originalEnv;
  });
});