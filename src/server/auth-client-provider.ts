/**
 * AuthClientProvider manages AuthClient instances for multiple custom domains
 * @internal
 */

import { InvalidConfigurationError } from "../errors/index.js";
import { DomainResolutionError } from "../errors/mcd.js";
import type {
  BackchannelLogoutConfig,
  DomainResolver,
  TrustedDomainsResolver
} from "../types/mcd.js";
import { LruMap } from "../utils/lru-map.js";
import { normalizeDomain } from "../utils/normalize.js";
import type { AuthClient } from "./auth-client.js";

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
   * Optional BCLO trust configuration (resolver mode only).
   * In resolver mode, specifies which domains' logout tokens to accept.
   * In static mode, this is ignored.
   */
  backchannelLogout?: BackchannelLogoutConfig;
}

/**
 * Maximum number of domain clients to cache.
 * This prevents unbounded memory growth when using a domain resolver.
 */
const MAX_DOMAIN_CLIENTS = 100;

/**
 * Maximum number of proxy fetchers to cache.
 * This prevents unbounded memory growth when many unique audience/domain
 * combinations are used. Uses LRU eviction matching the domain clients pattern.
 */
const MAX_PROXY_FETCHERS = 100;

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

  private domainClients: LruMap<string, AuthClient>;

  private createAuthClientFactory: (domain: string) => AuthClient;
  private proxyFetchers: LruMap<string, any>;

  // BCLO trust configuration (resolver mode only)
  private trustedDomainsConfig?: string[] | TrustedDomainsResolver;
  private trustedDomainsNormalized?: string[]; // Cached normalized array (static case only)
  private isResolverFunction: boolean = false; // Track if resolver or static array
  public hasTrustedDomains: boolean = false; // Public flag for BCLO handler check

  /**
   * Creates a new AuthClientProvider instance.
   *
   * @param options - Configuration options
   * @throws {InvalidConfigurationError} If configuration is invalid (neither domain nor resolver)
   *
   * @internal
   */
  constructor(options: AuthClientProviderOptions) {
    this.createAuthClientFactory = options.createAuthClient;

    // Initialize LRU caches
    this.domainClients = new LruMap(MAX_DOMAIN_CLIENTS);
    this.proxyFetchers = new LruMap(MAX_PROXY_FETCHERS);

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
      throw new InvalidConfigurationError(
        "You must provide either a domain string or a DomainResolver function."
      );
    }

    // Initialize BCLO trust configuration
    if (options.backchannelLogout?.trustedDomains) {
      this.trustedDomainsConfig = options.backchannelLogout.trustedDomains;
      this.hasTrustedDomains = true;

      // If static array, normalize upfront for performance
      if (Array.isArray(this.trustedDomainsConfig)) {
        this.trustedDomainsNormalized = this.trustedDomainsConfig
          .map((td) => {
            try {
              return normalizeDomain(td).domain;
            } catch (e) {
              // Skip invalid entries with warning
              console.warn(
                `[Auth0] Invalid domain in backchannelLogout.trustedDomains: ${td}. Skipping.`
              );
              return null;
            }
          })
          .filter((d): d is string => d !== null);
        this.isResolverFunction = false;
      } else {
        // Resolver function
        this.isResolverFunction = true;
      }
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

    // Cache key is the normalized domain hostname.
    // When mTLS support is added, extend key to `${domain}:${mtlsEnabled}`
    // to cache separate AuthClient instances per mTLS mode (cf. server-js PR #119).
    const client = this.domainClients.get(normalizedDomain);
    if (client) {
      return client;
    }
    // Create new client (LruMap.set() handles eviction)
    const newClient = this.createAuthClientFactory(normalizedDomain);
    this.domainClients.set(normalizedDomain, newClient);
    return newClient;
  }

  /**
   * Validates if a domain is in the trusted domains list.
   *
   * Used by BCLO handler to validate issuer claims before token verification.
   * Returns true if domain is whitelisted, false otherwise.
   *
   * In resolver mode:
   * - If trustedDomains is a function, calls it and compares normalized result
   * - If trustedDomains is an array, compares against pre-normalized array
   *
   * In static mode or if no trustedDomains configured: returns false
   * (BCLO is not using trust validation in these cases)
   *
   * @param domain - The domain to validate (may be extracted from issuer URL)
   * @returns True if domain is trusted, false otherwise
   *
   * @internal
   */
  async isTrustedDomain(domain: string): Promise<boolean> {
    // Not configured: not trusted
    if (!this.trustedDomainsConfig || !this.hasTrustedDomains) {
      return false;
    }

    // Normalize the input domain
    let normalizedInputDomain: string;
    try {
      ({ domain: normalizedInputDomain } = normalizeDomain(domain));
    } catch (e) {
      // Invalid domain format: not trusted
      return false;
    }

    if (this.isResolverFunction) {
      // Resolver mode: call function and check result
      const resolverFn = this.trustedDomainsConfig as TrustedDomainsResolver;
      try {
        const trustedDomains = await resolverFn();
        if (!Array.isArray(trustedDomains)) {
          console.warn("[Auth0] trustedDomains resolver must return an array.");
          return false;
        }

        // Normalize and compare each entry
        return trustedDomains.some((td) => {
          try {
            const { domain: normalizedTd } = normalizeDomain(td);
            return (
              normalizedTd.toLowerCase() === normalizedInputDomain.toLowerCase()
            );
          } catch {
            // Skip invalid entries
            return false;
          }
        });
      } catch (error) {
        // Resolver threw: fail closed (not trusted)
        console.warn(
          `[Auth0] trustedDomains resolver threw an error: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        return false;
      }
    } else {
      // Static array mode: compare against pre-normalized list
      return (
        this.trustedDomainsNormalized?.some(
          (td) => td.toLowerCase() === normalizedInputDomain.toLowerCase()
        ) ?? false
      );
    }
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
    // Check cache first (LruMap.get() handles promotion)
    const fetcher = this.proxyFetchers.get(key);
    if (fetcher) {
      return fetcher;
    }
    // Create new fetcher (LruMap.set() handles eviction)
    const newFetcher = await factory();
    this.proxyFetchers.set(key, newFetcher);
    return newFetcher;
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
      throw new InvalidConfigurationError("Domain resolver is not configured.");
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
