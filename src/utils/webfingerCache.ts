/**
 * Enterprise Connect domain discovery.
 *
 * Wraps Auth0's WebFinger endpoint (RFC 7033) to determine whether an email
 * domain is managed for enterprise SSO on a tenant, with a short-lived TTL
 * cache to stay well inside the endpoint's rate limits.
 */

interface CacheEntry {
  result: boolean;
  /** Absolute expiry, `Date.now()` based (milliseconds). */
  expiresAt: number;
}

const _cache = new Map<string, CacheEntry>();

/**
 * TTL for a positive result. Matches the server's `Cache-Control` for
 * managed domains. A removed domain can appear federated for up to this
 * long, which is safe: the user is routed to Auth0 where the actual
 * authentication fails cleanly.
 */
const TTL_TRUE_MS = 60_000;

/**
 * TTL for a negative result. Kept short so newly configured domains are
 * picked up quickly during customer onboarding.
 */
const TTL_FALSE_MS = 15_000;

const OIDC_REL = "http://openid.net/specs/connect/1.0/issuer";

/**
 * Checks whether an email domain is managed for enterprise SSO on an Auth0 tenant.
 *
 * This is a **routing hint, not a security control**. Always validate the
 * `org_id` claim on the resulting ID token regardless of what this returns.
 *
 * Server-side only. Calling this from the browser would expose the Auth0
 * domain and allow clients to enumerate your customers' domains.
 *
 * @param auth0Domain Your Auth0 tenant domain, e.g. `your-tenant.auth0.com`.
 * @param emailDomain The domain part of the user's email, e.g. `acmecorp.com`.
 *   Case-insensitive.
 * @returns `true` only when Auth0 has an enterprise connection or organization
 *   domain-discovery record for the domain. Returns `false` on any error, so a
 *   WebFinger outage degrades to your existing login flow rather than blocking it.
 *
 * @example
 * ```ts
 * const emailDomain = email.split("@")[1];
 * if (await isFederatedDomain(process.env.AUTH0_DOMAIN!, emailDomain)) {
 *   // route through Auth0 SSO
 * } else {
 *   // route through your existing login
 * }
 * ```
 */
export async function isFederatedDomain(
  auth0Domain: string,
  emailDomain: string
): Promise<boolean> {
  // The server lowercases the domain before lookup, so normalize here too —
  // otherwise "Acme.com" and "acme.com" would occupy separate cache entries
  // for what is a single server-side result.
  const normalizedDomain = emailDomain.toLowerCase();
  const key = `${auth0Domain}:${normalizedDomain}`;

  const cached = _cache.get(key);
  if (cached !== undefined) {
    if (Date.now() < cached.expiresAt) {
      return cached.result;
    }
    _cache.delete(key);
  }

  try {
    const res = await fetch(
      `https://${auth0Domain}/.well-known/webfinger` +
        `?resource=urn:auth0:discovery:domain:${encodeURIComponent(normalizedDomain)}` +
        `&rel=${OIDC_REL}`
    );

    if (res.ok) {
      const body = await res.json();
      const managed =
        Array.isArray(body?.links) &&
        body.links.some((link: { rel?: string }) => link?.rel === OIDC_REL);

      if (managed) {
        _cache.set(key, { result: true, expiresAt: Date.now() + TTL_TRUE_MS });
        return true;
      }

      // 200 with no matching rel is ambiguous — the tenant may be mid-configuration.
      // Not cached, so the next attempt re-checks.
      return false;
    }

    if (res.status === 404) {
      _cache.set(key, { result: false, expiresAt: Date.now() + TTL_FALSE_MS });
      return false;
    }

    if (res.status === 429) {
      // Rate limited. Not cached — caching would extend the outage past the
      // limit window. The TTLs above are the primary defense against this;
      // hitting 429 means the cache missed (cold start, or many distinct
      // domains at once). Warn so this is not a silent SSO bypass.
      console.warn(
        "[Auth0] isFederatedDomain: rate limit hit (429). Enterprise SSO routing " +
          "is temporarily unavailable and users on federated domains will fall " +
          "through to your default login. Check x-ratelimit-reset for retry timing."
      );
      return false;
    }

    // 403 means the endpoint is disabled for the tenant; 5xx is a server fault.
    // Neither is cached — both can be fixed without a client deploy.
  } catch {
    // Network failure or malformed JSON. Never cached.
  }

  return false;
}

/**
 * Clears the module-level cache.
 *
 * @internal Test helper. Not part of the public API.
 */
export function _clearWebFingerCacheForTesting(): void {
  _cache.clear();
}
