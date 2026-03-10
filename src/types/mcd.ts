/**
 * MCD (Multiple Custom Domains) types and interfaces.
 *
 * Public exports: {@link DomainResolver}, {@link DiscoveryCacheOptions}.
 * Internal: {@link MCDMetadata}, {@link SessionCheckResult}.
 */

import type { SdkError } from "../errors/sdk-error.js";
import type { SessionData } from "./index.js";

/**
 * Resolves the Auth0 domain from request context.
 * Called once per SDK operation in resolver mode.
 *
 * Supports both synchronous and asynchronous resolution patterns.
 *
 * @param config.headers - Request headers from the current context.
 *   In App Router Server Components / Server Actions: obtained via `headers()` from `next/headers`.
 *   In Middleware / Route Handlers: extracted from `NextRequest`.
 *   In Pages Router (`getServerSideProps`, API Routes): extracted from `IncomingMessage`.
 *
 * @param config.url - The request URL, when available.
 *   In Middleware / Route Handlers: the full `NextRequest.nextUrl` (includes pathname, search params).
 *   In Pages Router: constructed from `IncomingMessage.url` + Host header.
 *   In App Router Server Components / Server Actions: `undefined` (no request object exists).
 *   Use this for B2B multi-tenant routing where the application hostname determines the Auth0 domain.
 *
 * @returns The Auth0 custom domain hostname (e.g., `"auth.brand1.com"`).
 *   Can be returned synchronously or as a Promise.
 *   Must throw on resolution failure — the SDK wraps thrown errors in {@link DomainResolutionError}.
 *
 * @security The resolver is responsible for preventing Host Header injection attacks.
 *   The SDK validates the resolver's output via `normalizeDomain` (hostname format validation),
 *   but input validation and SSRF prevention are the customer's responsibility.
 *
 * @example
 * // Header-based routing (B2C multi-brand)
 * const auth0 = new Auth0Client({
 *   domain: ({ headers }) => {
 *     const host = headers.get("host") ?? "";
 *     if (host.startsWith("brand1.")) return "auth.brand1.com";
 *     if (host.startsWith("brand2.")) return "auth.brand2.com";
 *     return "auth.default.com";
 *   }
 * });
 *
 * @example
 * // Database lookup (B2B SaaS)
 * const auth0 = new Auth0Client({
 *   domain: async ({ headers }) => {
 *     const tenantId = headers.get("x-tenant-id");
 *     const domain = await db.getAuth0Domain(tenantId);
 *     if (!domain) throw new Error(`Unknown tenant: ${tenantId}`);
 *     return domain;
 *   }
 * });
 *
 * @public
 */
export type DomainResolver = (config: {
  headers: Headers;
  url?: URL;
}) => Promise<string> | string;

/**
 * Configuration for the OIDC discovery metadata cache.
 * Applies in both static and resolver modes.
 *
 * @property ttl - Time-to-live for cached discovery metadata in seconds. Default: 600 (10 minutes).
 * @property maxEntries - Maximum number of cached issuers. Default: 100. LRU eviction.
 * @property maxJwksEntries - Maximum number of cached JWKS entries. Default: 10. Independent LRU eviction.
 *
 * @example
 * ```typescript
 * const auth0 = new Auth0Client({
 *   domain: myDomainResolver,
 *   discoveryCache: {
 *     ttl: 300,        // 5-minute TTL
 *     maxEntries: 50,  // Cache up to 50 issuers
 *   }
 * });
 * ```
 *
 * @public
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

/**
 * Result of a session domain check operation.
 *
 * @field error - SDK error object (null if no error). Includes SessionDomainMismatchError on domain mismatch.
 * @field session - The session data, or null if not found, domain mismatch, or error occurred.
 * @field exists - Whether a session physically exists in the store (true even if domain mismatch or error).
 *                 Distinguishes "no session" from "session found but domain mismatch/error".
 *
 * Callers MUST check error first before using session.
 *
 * @internal
 */
export interface SessionCheckResult {
  error: SdkError | null;
  session: SessionData | null;
  exists: boolean;
}
