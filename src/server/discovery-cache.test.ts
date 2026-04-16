/**
 * Tests for the DiscoveryCache class
 */

import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DiscoveryCache } from "./discovery-cache.js";

describe("DiscoveryCache", () => {
  let cache: DiscoveryCache;

  beforeEach(() => {
    vi.clearAllMocks();
    cache = new DiscoveryCache();
  });

  describe("cache hit and miss", () => {
    it("should call fetchMetadata on cache miss", async () => {
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };
      const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

      const result = await cache.get("example.auth0.com", fetchMetadata);

      expect(fetchMetadata).toHaveBeenCalledWith("example.auth0.com");
      expect(result).toEqual(mockMetadata);
    });

    it("should return cached result on cache hit", async () => {
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };
      const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

      // First call
      await cache.get("example.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const result = await cache.get("example.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(1); // Still 1, not 2
      expect(result).toEqual(mockMetadata);
    });

    it("should not call fetchMetadata again if in cache", async () => {
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };
      const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain1.auth0.com", fetchMetadata);

      expect(fetchMetadata).toHaveBeenCalledTimes(1);
    });
  });

  describe("TTL expiry", () => {
    it("should re-fetch after TTL expires", async () => {
      vi.useFakeTimers();
      try {
        const ttl = 10; // 10 seconds
        cache = new DiscoveryCache({ ttl });

        const mockMetadata: oauth.AuthorizationServer = {
          issuer: "https://example.auth0.com",
          token_endpoint: "https://example.auth0.com/oauth/token",
          jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
        };
        const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

        // First call
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1);

        // Advance time within TTL
        vi.advanceTimersByTime(5000); // 5 seconds
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1); // Still in cache

        // Advance time past TTL
        vi.advanceTimersByTime(6000); // Total 11 seconds
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(2); // Cache expired, refetch
      } finally {
        vi.useRealTimers();
      }
    });

    it("should use custom TTL if provided", async () => {
      vi.useFakeTimers();
      try {
        const ttl = 3600; // 1 hour
        cache = new DiscoveryCache({ ttl });

        const mockMetadata: oauth.AuthorizationServer = {
          issuer: "https://example.auth0.com",
          token_endpoint: "https://example.auth0.com/oauth/token",
          jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
        };
        const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

        // First call
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1);

        // Advance time 30 minutes (within TTL)
        vi.advanceTimersByTime(30 * 60 * 1000);
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1); // Still in cache

        // Advance time to 1 hour and 1 second (past TTL)
        vi.advanceTimersByTime(31 * 60 * 1000);
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(2); // Cache expired
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("in-flight deduplication", () => {
    it("should deduplicate concurrent requests for same domain", async () => {
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };

      let fetchCount = 0;
      const fetchMetadata = vi.fn().mockImplementation(async () => {
        fetchCount++;
        // Simulate network delay
        await new Promise((resolve) => setTimeout(resolve, 50));
        return mockMetadata;
      });

      // Make 5 concurrent calls
      const promises = Array.from({ length: 5 }, () =>
        cache.get("example.auth0.com", fetchMetadata)
      );

      await Promise.all(promises);

      // fetchMetadata should be called only once despite 5 concurrent requests
      expect(fetchCount).toBe(1);
      expect(fetchMetadata).toHaveBeenCalledTimes(1);
    });

    it("should handle different domains concurrently", async () => {
      const mockMetadata1: oauth.AuthorizationServer = {
        issuer: "https://domain1.auth0.com",
        token_endpoint: "https://domain1.auth0.com/oauth/token",
        jwks_uri: "https://domain1.auth0.com/.well-known/jwks.json"
      };
      const mockMetadata2: oauth.AuthorizationServer = {
        issuer: "https://domain2.auth0.com",
        token_endpoint: "https://domain2.auth0.com/oauth/token",
        jwks_uri: "https://domain2.auth0.com/.well-known/jwks.json"
      };

      const fetchMetadata = vi.fn().mockImplementation(async (domain) => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return domain === "domain1.auth0.com" ? mockMetadata1 : mockMetadata2;
      });

      // Make concurrent calls for different domains
      const promise1 = cache.get("domain1.auth0.com", fetchMetadata);
      const promise2 = cache.get("domain2.auth0.com", fetchMetadata);

      const result1 = await promise1;
      const result2 = await promise2;

      expect(result1).toEqual(mockMetadata1);
      expect(result2).toEqual(mockMetadata2);
      expect(fetchMetadata).toHaveBeenCalledTimes(2);
    });

    it("should propagate failure to all concurrent waiters and allow retry", async () => {
      let callCount = 0;
      const fetchMetadata = vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          throw new Error("Network error");
        }
        return {
          issuer: "https://example.auth0.com/",
          token_endpoint: "https://example.auth0.com/oauth/token",
          jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
        } as oauth.AuthorizationServer;
      });

      // Launch concurrent requests that share the same pending promise
      const promise1 = cache.get("example.auth0.com", fetchMetadata);
      const promise2 = cache.get("example.auth0.com", fetchMetadata);
      const promise3 = cache.get("example.auth0.com", fetchMetadata);

      // All should reject with the same error
      await expect(promise1).rejects.toThrow("Network error");
      await expect(promise2).rejects.toThrow("Network error");
      await expect(promise3).rejects.toThrow("Network error");

      // Only one fetch call should have been made (deduplication)
      expect(fetchMetadata).toHaveBeenCalledTimes(1);

      // After failure, a new request should trigger a fresh fetch (retry works)
      const result = await cache.get("example.auth0.com", fetchMetadata);
      expect(result.issuer).toBe("https://example.auth0.com/");
      expect(fetchMetadata).toHaveBeenCalledTimes(2);
    });
  });

  describe("LRU eviction", () => {
    it("should evict oldest entry when maxEntries is reached", async () => {
      cache = new DiscoveryCache({ maxEntries: 3 });

      const fetchMetadata = vi.fn().mockImplementation(async (domain) => ({
        issuer: `https://${domain}`,
        token_endpoint: `https://${domain}/oauth/token`,
        jwks_uri: `https://${domain}/.well-known/jwks.json`
      }));

      // Add 3 domains to fill cache
      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain2.auth0.com", fetchMetadata);
      await cache.get("domain3.auth0.com", fetchMetadata);
      const callsAfter3 = fetchMetadata.mock.calls.length;
      expect(callsAfter3).toBe(3);

      // Add 4th domain - should evict oldest (domain1)
      await cache.get("domain4.auth0.com", fetchMetadata);
      const callsAfter4 = fetchMetadata.mock.calls.length;
      expect(callsAfter4).toBe(4); // One new call for domain4

      // Request domain1 again - should fetch since it was evicted
      await cache.get("domain1.auth0.com", fetchMetadata);
      const callsAfter1Again = fetchMetadata.mock.calls.length;
      expect(callsAfter1Again).toBe(5); // One new call for domain1 (was evicted)
    });

    it("should promote entry on cache hit (LRU)", async () => {
      cache = new DiscoveryCache({ maxEntries: 3 });

      const fetchMetadata = vi.fn().mockImplementation(async (domain) => ({
        issuer: `https://${domain}`,
        token_endpoint: `https://${domain}/oauth/token`,
        jwks_uri: `https://${domain}/.well-known/jwks.json`
      }));

      // Add 3 domains
      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain2.auth0.com", fetchMetadata);
      await cache.get("domain3.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(3);

      // Access domain1 again - should promote it
      await cache.get("domain1.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(3); // Still 3

      // Add domain4 - should evict domain2 (oldest after domain1 was promoted)
      await cache.get("domain4.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(4);

      // domain2 should be evicted
      await cache.get("domain2.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(5);

      // domain1 should still be in cache
      await cache.get("domain1.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(5); // No new call
    });
  });

  describe("rejection cleanup", () => {
    it("should remove in-flight entry if fetch fails", async () => {
      const error = new Error("Network error");
      const fetchMetadata = vi.fn().mockRejectedValue(error);

      // First attempt fails
      await expect(
        cache.get("example.auth0.com", fetchMetadata)
      ).rejects.toThrow("Network error");

      // Mock should be called once
      expect(fetchMetadata).toHaveBeenCalledTimes(1);

      // Second attempt should retry (not use cached promise from first failure)
      const fetchMetadata2 = vi.fn().mockResolvedValue({
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      });

      const result = await cache.get("example.auth0.com", fetchMetadata2);
      expect(result).toBeDefined();
      expect(fetchMetadata2).toHaveBeenCalledTimes(1);
    });

    it("should not cache failed fetches", async () => {
      const error = new Error("Fetch failed");
      const fetchMetadata = vi.fn().mockRejectedValue(error);

      // First attempt fails
      await expect(
        cache.get("example.auth0.com", fetchMetadata)
      ).rejects.toThrow();

      // Subsequent attempts should retry
      await expect(
        cache.get("example.auth0.com", fetchMetadata)
      ).rejects.toThrow();
      await expect(
        cache.get("example.auth0.com", fetchMetadata)
      ).rejects.toThrow();

      // Should call fetchMetadata 3 times (no caching)
      expect(fetchMetadata).toHaveBeenCalledTimes(3);
    });
  });

  describe("JWKS cache", () => {
    it("should create new JWKS cache entry", () => {
      const jwksUri = "https://example.auth0.com/.well-known/jwks.json";
      const cache1 = cache.getJwksCacheForUri(jwksUri);

      expect(cache1).toBeDefined();
      expect(typeof cache1).toBe("object");
    });

    it("should return same JWKS cache entry on subsequent calls", () => {
      const jwksUri = "https://example.auth0.com/.well-known/jwks.json";
      const cache1 = cache.getJwksCacheForUri(jwksUri);
      const cache2 = cache.getJwksCacheForUri(jwksUri);

      expect(cache1).toBe(cache2);
    });

    it("should maintain separate JWKS cache for different URIs", () => {
      const jwksUri1 = "https://domain1.auth0.com/.well-known/jwks.json";
      const jwksUri2 = "https://domain2.auth0.com/.well-known/jwks.json";

      const cache1 = cache.getJwksCacheForUri(jwksUri1);
      const cache2 = cache.getJwksCacheForUri(jwksUri2);

      expect(cache1).not.toBe(cache2);
    });
  });

  describe("clear", () => {
    it("should clear all cached entries", async () => {
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };
      const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

      // Populate cache
      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain2.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(2);

      // Clear cache
      cache.clear();

      // Subsequent calls should fetch again
      await cache.get("domain1.auth0.com", fetchMetadata);
      await cache.get("domain2.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(4);
    });

    it("should clear JWKS cache", () => {
      const jwksUri = "https://example.auth0.com/.well-known/jwks.json";
      const cache1 = cache.getJwksCacheForUri(jwksUri);

      cache.clear();

      const cache2 = cache.getJwksCacheForUri(jwksUri);
      expect(cache1).not.toBe(cache2);
    });

    it("should clear in-flight promises", async () => {
      const fetchMetadata = vi.fn().mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(
              () =>
                resolve({
                  issuer: "https://example.auth0.com",
                  token_endpoint: "https://example.auth0.com/oauth/token",
                  jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
                }),
              100
            )
          )
      );

      // Start fetching but don't wait
      const promise1 = cache.get("example.auth0.com", fetchMetadata);

      // Clear immediately
      cache.clear();

      // Start a new fetch - should call fetchMetadata again
      const fetchMetadata2 = vi.fn().mockResolvedValue({
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      });

      const promise2 = cache.get("example.auth0.com", fetchMetadata2);

      await promise1;
      await promise2;

      // Both fetchMetadata functions should have been called
      expect(fetchMetadata).toHaveBeenCalledTimes(1);
      expect(fetchMetadata2).toHaveBeenCalledTimes(1);
    });
  });

  describe("default configuration", () => {
    it("should use default TTL of 600 seconds", async () => {
      cache = new DiscoveryCache();
      const mockMetadata: oauth.AuthorizationServer = {
        issuer: "https://example.auth0.com",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      };
      const fetchMetadata = vi.fn().mockResolvedValue(mockMetadata);

      vi.useFakeTimers();
      try {
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1);

        // Advance 599 seconds (still within TTL)
        vi.advanceTimersByTime(599 * 1000);
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(1); // Still cached

        // Advance 2 seconds (601 total, past TTL)
        vi.advanceTimersByTime(2 * 1000);
        await cache.get("example.auth0.com", fetchMetadata);
        expect(fetchMetadata).toHaveBeenCalledTimes(2); // Refetched
      } finally {
        vi.useRealTimers();
      }
    });

    it("should use default maxEntries of 100", async () => {
      cache = new DiscoveryCache();
      const fetchMetadata = vi.fn().mockImplementation(async (domain) => ({
        issuer: `https://${domain}`,
        token_endpoint: `https://${domain}/oauth/token`,
        jwks_uri: `https://${domain}/.well-known/jwks.json`
      }));

      // Add 100 domains
      for (let i = 0; i < 100; i++) {
        await cache.get(`domain${i}.auth0.com`, fetchMetadata);
      }
      expect(fetchMetadata).toHaveBeenCalledTimes(100);

      // Add 101st domain - should evict oldest
      await cache.get("domain100.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(101);

      // domain0 should be evicted
      await cache.get("domain0.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(102);
    });

    it("[POST-IMPL-5] Discovery cache LRU promotion on cache hit", async () => {
      cache = new DiscoveryCache({ maxEntries: 3 });

      const fetchMetadata = vi.fn().mockImplementation(async (domain) => ({
        issuer: `https://${domain}`,
        token_endpoint: `https://${domain}/oauth/token`,
        jwks_uri: `https://${domain}/.well-known/jwks.json`
      }));

      // Add 3 domains
      await cache.get("domainA.auth0.com", fetchMetadata);
      await cache.get("domainB.auth0.com", fetchMetadata);
      await cache.get("domainC.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(3);

      // Re-access domainA to promote it
      await cache.get("domainA.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(3); // Cache hit

      // Add domainD - should evict domainB (oldest after A was promoted)
      await cache.get("domainD.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(4);

      // domainB should be evicted
      await cache.get("domainB.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(5);

      // domainA should still be cached
      await cache.get("domainA.auth0.com", fetchMetadata);
      expect(fetchMetadata).toHaveBeenCalledTimes(5); // Still cached
    });
  });
});
