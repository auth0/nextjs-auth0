/**
 * AuthClientProvider manages AuthClient instances for multiple custom domains
 * @internal
 */

import {
  DomainResolutionError,
  McdInvalidConfigurationError
} from "../errors/mcd.js";
import type { DomainResolver } from "../types/mcd.js";
import { normalizeDomain } from "../utils/normalize.js";
import type { AuthClient } from "./auth-client.js";
import { DiscoveryCache } from "./discovery-cache.js";

/**
 * Options for AuthClientProvider.
 */
interface AuthClientProviderOptions {
  /**
   * Either a static domain string or a DomainResolver function.
   * If a string, operates in static mode.
   * If a function, operates in resolver mode.
   */
  domain: string | DomainResolver;

  /**
   * Factory function to create an AuthClient for a given domain.
   * Called when a new domain client is needed.
   */
  createAuthClient: (domain: string) => AuthClient;

  /**
   * Discovery cache options for sharing metadata across domains.
   */
  discoveryCacheOptions?: {
    ttl?: number;
    maxEntries?: number;
    maxJwksEntries?: number;
  };
}

/**
 * Maximum number of domain clients to cache.
 * This prevents unbounded memory growth when using a domain resolver.
 */
const MAX_DOMAIN_CLIENTS = 100;

/**
 * Helper to get the first key from a Map (for LRU eviction).
 */
function getFirstMapKey<K>(map: Map<K, any>): K | undefined {
  return map.keys().next().value;
}

/**
 * AuthClientProvider manages creating and caching AuthClient instances for MCD mode.
 *
 * Features:
 * - Detects static vs resolver mode from configuration
 * - Pre-populates cache in static mode
 * - Provides request-scoped access via forRequest() in resolver mode
 * - Maintains bounded LRU cache of domain clients
 * - Shares discovery cache across all domains
 *
 * @internal
 */
export class AuthClientProvider {
  private mode: "static" | "resolver";
  private staticDomain?: string;
  private resolver?: DomainResolver;

  private domainClients: Map<string, AuthClient> = new Map();
  private discoveryCache: DiscoveryCache;

  private createAuthClientFactory: (domain: string) => AuthClient;
  private proxyFetchers: Map<string, any> = new Map();

  /**
   * Creates a new AuthClientProvider instance.
   *
   * @param options - Configuration options
   * @throws {McdInvalidConfigurationError} If configuration is invalid (neither domain nor resolver)
   *
   * @internal
   */
  constructor(options: AuthClientProviderOptions) {
    this.createAuthClientFactory = options.createAuthClient;
    this.discoveryCache = new DiscoveryCache(options.discoveryCacheOptions);

    // Detect mode and validate configuration
    if (typeof options.domain === "string") {
      // Static mode: normalize and validate domain
      this.mode = "static";
      const normalized = normalizeDomain(options.domain, {
        allowInsecureRequests: process.env.NODE_ENV === "test"
      });
      this.staticDomain = normalized.domain;

      // Pre-populate cache with singleton AuthClient for static domain
      const client = this.createAuthClientFactory(this.staticDomain);
      this.domainClients.set(this.staticDomain, client);
    } else if (typeof options.domain === "function") {
      // Resolver mode: store resolver function
      this.mode = "resolver";
      this.resolver = options.domain;
    } else {
      throw new McdInvalidConfigurationError(
        "You must provide either a domain string or a DomainResolver function."
      );
    }
  }

  /**
   * Returns the configured static domain (if in static mode).
   *
   * @returns The static domain, or undefined if in resolver mode
   *
   * @internal
   */
  get configuredDomain(): string | undefined {
    return this.staticDomain;
  }

  /**
   * Returns true if operating in resolver mode, false in static mode.
   *
   * @returns True if using a domain resolver, false if using a static domain
   *
   * @internal
   */
  get isResolverMode(): boolean {
    return this.mode === "resolver";
  }

  /**
   * Gets the AuthClient for static mode (if available).
   *
   * Used internally to update provider references after construction.
   *
   * @returns The cached AuthClient in static mode, or undefined in resolver mode
   *
   * @internal
   */
  getAuthClientForStaticMode(): AuthClient | undefined {
    if (this.mode === "static" && this.staticDomain) {
      return this.domainClients.get(this.staticDomain);
    }
    return undefined;
  }

  /**
   * Gets an AuthClient for the current request in resolver mode.
   *
   * In static mode, always returns the same cached client.
   * In resolver mode, resolves the domain from headers and caches the client.
   *
   * @param headers - Request headers used for domain resolution
   * @param url - Optional request URL for enhanced domain resolution
   * @returns A promise resolving to the appropriate AuthClient
   * @throws {DomainResolutionError} If domain resolution fails
   *
   * @internal
   */
  async forRequest(headers: Headers, url?: URL): Promise<AuthClient> {
    if (this.mode === "static" && this.staticDomain) {
      // Static mode: always return the pre-cached client
      return this.domainClients.get(this.staticDomain)!;
    }

    // Resolver mode: resolve domain and get/create client
    const domain = await this.resolveDomain(headers, url);
    return this.forDomainSync(domain);
  }

  /**
   * Gets an AuthClient for a specific domain synchronously.
   *
   * Uses bounded LRU caching. If the cache exceeds MAX_DOMAIN_CLIENTS,
   * the oldest entry is evicted.
   *
   * @param domain - The domain to get a client for
   * @returns The AuthClient for the domain
   *
   * @internal
   */
  forDomainSync(domain: string): AuthClient {
    // Normalize and validate the domain
    const normalized = normalizeDomain(domain);
    const normalizedDomain = normalized.domain;

    // Check cache first
    let client = this.domainClients.get(normalizedDomain);
    if (client) {
      return client;
    }

    // Create new client
    client = this.createAuthClientFactory(normalizedDomain);
    this.domainClients.set(normalizedDomain, client);

    // Enforce max entries boundary with LRU eviction
    while (this.domainClients.size > MAX_DOMAIN_CLIENTS) {
      const oldestKey = getFirstMapKey(this.domainClients);
      if (oldestKey !== undefined) {
        this.domainClients.delete(oldestKey);
      }
    }

    return client;
  }

  /**
   * Gets a proxy fetcher from cache or creates one via the provided factory.
   *
   * Proxy fetchers are cached per key to avoid creating multiple instances
   * for the same audience or configuration.
   *
   * @param key - A unique key for the fetcher (e.g., "domain:audience")
   * @param factory - Factory function to create the fetcher if not cached
   * @returns The cached or newly created fetcher
   *
   * @internal
   */
  async getProxyFetcher(
    key: string,
    factory: () => Promise<any>
  ): Promise<any> {
    let fetcher = this.proxyFetchers.get(key);
    if (!fetcher) {
      fetcher = await factory();
      this.proxyFetchers.set(key, fetcher);
    }
    return fetcher;
  }

  /**
   * Gets the shared discovery cache used across all domains.
   *
   * @returns The DiscoveryCache instance
   *
   * @internal
   */
  getDiscoveryCache(): DiscoveryCache {
    return this.discoveryCache;
  }

  /**
   * Resolves the domain from request headers using the resolver function.
   *
   * Only valid in resolver mode.
   *
   * @param headers - Request headers
   * @param url - Optional request URL for enhanced domain resolution
   * @returns A promise resolving to the resolved domain
   * @throws {DomainResolutionError} If resolution fails or returns empty string
   *
   * @private
   * @internal
   */
  private async resolveDomain(headers: Headers, url?: URL): Promise<string> {
    if (!this.resolver) {
      throw new McdInvalidConfigurationError(
        "Domain resolver is not configured."
      );
    }

    let resolved: string;
    try {
      resolved = await this.resolver({ headers, url });
    } catch (err) {
      const cause = err instanceof Error ? err : new Error(String(err));
      throw new DomainResolutionError("Domain resolver threw an error.", cause);
    }

    if (!resolved) {
      throw new DomainResolutionError(
        "Domain resolver returned an empty string."
      );
    }

    // Normalize the resolved domain
    const normalized = normalizeDomain(resolved);
    return normalized.domain;
  }
}
