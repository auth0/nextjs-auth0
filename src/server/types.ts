/**
 * MCD (Multiple Custom Domains) types and interfaces
 * @internal
 */

/**
 * A function that resolves the domain for the current request based on headers and URL.
 * Used in resolver mode to dynamically determine which domain should handle authentication.
 *
 * Supports both synchronous and asynchronous resolution patterns.
 *
 * @param config - Configuration object containing request headers and optional URL
 *   - headers: Request headers from current context
 *   - url?: Request URL, when available. Undefined in Server Components/Actions.
 * @returns The domain string.
 *   Can be returned synchronously or as a Promise.
 *   Must throw on resolution failure (not return null). SDK wraps thrown errors in DomainResolutionError.
 *
 * @example
 * // Synchronous resolver with URL-based routing
 * const domain = {
 *   domain: ({ headers, url }) => {
 *     const hostname = url?.hostname || headers.get("host");
 *     if (hostname?.startsWith("brand1.")) return "auth.brand1.com";
 *     return "auth.example.com";
 *   }
 * };
 *
 * @example
 * // Asynchronous resolver with database lookup
 * const domain = {
 *   domain: async ({ headers, url }) => {
 *     const hostname = url?.hostname || headers.get("host");
 *     const resolvedDomain = await db.getDomain(hostname);
 *     if (!resolvedDomain) throw new Error("Domain not found");
 *     return resolvedDomain;
 *   }
 * };
 *
 * @internal
 */
export type DomainResolver = (config: {
  headers: Headers;
  url?: URL;
}) => Promise<string> | string;

/**
 * Configuration options for the discovery cache used in domain resolution.
 *
 * @property ttl - Time-to-live for cached discovery metadata in seconds. Default: 600
 * @property maxEntries - Maximum number of domain metadata entries to cache. Default: 100
 * @property maxJwksEntries - Maximum number of JWKS entries to cache separately. Default: 10
 * @internal
 */
export interface DiscoveryCacheOptions {
  ttl?: number;
  maxEntries?: number;
  maxJwksEntries?: number;
}

/**
 * Metadata for a specific domain and its associated issuer.
 * Stored in session internal state to track which domain authenticated the user.
 *
 * @property domain - The Auth0 domain that authenticated the user
 * @property issuer - The OIDC issuer URL for the domain
 * @internal
 */
export interface MCDMetadata {
  domain: string;
  issuer: string;
}
