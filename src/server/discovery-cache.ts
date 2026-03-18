/**
 * Discovery cache for OIDC metadata with in-flight request deduplication
 * @internal
 */

import type * as jose from "jose";
import * as oauth from "oauth4webapi";

/**
 * Helper to get the first key from a Map (for LRU eviction).
 */
function getFirstMapKey<K>(map: Map<K, any>): K | undefined {
  return map.keys().next().value;
}

/**
 * Entry in the discovery cache for OIDC metadata.
 *
 * @internal
 */
interface DiscoveryCacheEntry {
  /**
   * The cached OIDC discovery metadata for the domain
   */
  metadata: oauth.AuthorizationServer;

  /**
   * Timestamp (seconds since epoch) when this entry expires
   */
  expiresAt: number;
}

/**
 * Options for the discovery cache.
 */
interface CacheOptions {
  /**
   * Time-to-live in seconds for cached entries. Default: 600
   */
  ttl?: number;

  /**
   * Maximum number of domain entries to cache. Default: 100
   */
  maxEntries?: number;
}

/**
 * Discovery cache for OIDC metadata with in-flight deduplication and JWKS caching.
 *
 * Features:
 * - LRU eviction when max entries is reached
 * - TTL-based lazy expiration
 * - In-flight request deduplication (multiple requests for the same domain are deduplicated)
 * - Automatic rejection cleanup if a request fails
 * - Co-located JWKS cache for jose
 * - Hard boundary eviction (LRU)
 *
 * @internal
 */
export class DiscoveryCache {
  private cache: Map<string, DiscoveryCacheEntry> = new Map();
  private inFlight: Map<string, Promise<oauth.AuthorizationServer>> = new Map();
  private jwksCache: Map<string, jose.JWKSCacheInput> = new Map();

  private ttl: number;
  private maxEntries: number;

  /**
   * Creates a new DiscoveryCache instance.
   *
   * @param options - Cache configuration options
   */
  constructor(options?: CacheOptions) {
    this.ttl = options?.ttl ?? 600; // 600 seconds = 10 minutes
    this.maxEntries = options?.maxEntries ?? 100;
  }

  /**
   * Gets or fetches discovery metadata for a domain.
   *
   * Implements in-flight deduplication: if multiple calls are made for the same domain
   * before the first completes, they all await the same promise.
   *
   * @param domain - The Auth0 domain to fetch metadata for
   * @param fetchMetadata - Async function that fetches the metadata if not cached
   * @returns A promise resolving to the authorization server metadata
   *
   * @internal
   */
  async get(
    domain: string,
    fetchMetadata: (domain: string) => Promise<oauth.AuthorizationServer>
  ): Promise<oauth.AuthorizationServer> {
    const now = Math.floor(Date.now() / 1000);

    // Check for unexpired cache entry
    const cached = this.cache.get(domain);
    if (cached && cached.expiresAt > now) {
      // LRU: delete and re-insert to move to end
      this.cache.delete(domain);
      this.cache.set(domain, cached);
      return cached.metadata;
    }

    // Check if a request is already in flight
    const inFlightPromise = this.inFlight.get(domain);
    if (inFlightPromise) {
      return inFlightPromise;
    }

    // Create a new fetch promise and store it synchronously BEFORE awaiting
    const fetchPromise = fetchMetadata(domain)
      .then((metadata) => {
        // Store in cache
        const expiresAt = now + this.ttl;
        this.cache.set(domain, { metadata, expiresAt });

        // Clean up in-flight entry
        this.inFlight.delete(domain);

        // Enforce max entries boundary with LRU eviction
        while (this.cache.size > this.maxEntries) {
          const oldestKey = getFirstMapKey(this.cache);
          if (oldestKey !== undefined) {
            this.cache.delete(oldestKey);
          }
        }

        return metadata;
      })
      .catch((err) => {
        // Remove the in-flight entry on failure so retries can proceed
        this.inFlight.delete(domain);
        throw err;
      });

    // Store in-flight promise BEFORE awaiting
    this.inFlight.set(domain, fetchPromise);

    return fetchPromise;
  }

  /**
   * Gets or creates a JWKS cache entry for the given JWKS URI.
   *
   * The JWKS cache is separate from the discovery metadata cache and has
   * its own size limit.
   *
   * @param jwksUri - The JWKS endpoint URI
   * @returns The JWKS cache object (jose.JWKSCacheInput format)
   *
   * @internal
   */
  getJwksCacheForUri(jwksUri: string): jose.JWKSCacheInput {
    let jwksEntry = this.jwksCache.get(jwksUri);

    if (!jwksEntry) {
      // Enforce max entries boundary BEFORE adding (LRU)
      if (this.jwksCache.size >= this.maxEntries) {
        const firstKey = getFirstMapKey(this.jwksCache);
        if (firstKey !== undefined) {
          this.jwksCache.delete(firstKey);
        }
      }

      jwksEntry = {};
      this.jwksCache.set(jwksUri, jwksEntry);
    } else {
      // LRU: delete and re-insert to move to end
      this.jwksCache.delete(jwksUri);
      this.jwksCache.set(jwksUri, jwksEntry);
    }

    return jwksEntry;
  }

  /**
   * Clears all cached entries (discovery metadata and JWKS cache).
   *
   * @internal
   */
  clear(): void {
    this.cache.clear();
    this.jwksCache.clear();
    this.inFlight.clear();
  }
}
