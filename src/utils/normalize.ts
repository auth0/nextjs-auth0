/**
 * Utilities for normalizing and validating domains and issuers in MCD mode.
 *
 * Note on validation strictness: This validator is stricter than other Auth0 SDKs
 * (spa-js, react, express-openid-connect do no hostname validation). The strictness
 * is intentional for MCD resolver mode where the domain originates from a user-supplied
 * function and SSRF prevention is critical. In static mode the same validation applies
 * for consistency, but IP addresses and .local domains are never valid Auth0 custom
 * domains regardless.
 *
 * @internal
 */

import { DomainValidationError } from "../errors/mcd.js";

/**
 * Normalizes an issuer URL by ensuring it has a trailing slash.
 *
 * @param issuer - The issuer URL to normalize
 * @returns The normalized issuer URL with a trailing slash
 * @internal
 */
export function normalizeIssuer(issuer: string): string {
  if (!issuer.endsWith("/")) {
    return issuer + "/";
  }
  return issuer;
}

/**
 * Options for domain validation.
 */
interface ValidateDomainHostnameOptions {
  /**
   * Allow insecure (HTTP) requests for testing purposes.
   * Default: false
   */
  allowInsecureRequests?: boolean;
}

/**
 * Validates a domain hostname to ensure it's a valid Auth0 custom domain.
 *
 * Auth0 custom domains must be DNS hostnames — IP addresses, localhost, and mDNS
 * (.local) domains are never valid Auth0 custom domains and are rejected
 * unconditionally (or conditionally for localhost when allowInsecureRequests is set).
 *
 * This is stricter than other Auth0 SDKs (spa-js, react, express-openid-connect
 * perform no hostname validation). The strictness is intentional for MCD resolver
 * mode where SSRF prevention is critical, and applies uniformly in static mode
 * for consistency.
 *
 * Rejects:
 * - IPv4 addresses (never valid Auth0 custom domains)
 * - IPv6 addresses (implicitly rejected via port/colon check)
 * - localhost (unless allowInsecureRequests for dev scenarios)
 * - .local domains (mDNS, unconditionally rejected)
 * - Hostnames with paths
 * - Hostnames with ports (unless already parsed)
 *
 * @param domain - The domain hostname to validate
 * @param options - Validation options
 * @throws {DomainValidationError} If the domain fails validation
 * @internal
 */
export function validateDomainHostname(
  domain: string,
  options?: ValidateDomainHostnameOptions
): void {
  const trimmed = domain.trim();

  // Reject empty domains
  if (!trimmed) {
    throw new DomainValidationError("Domain cannot be empty.");
  }

  // Reject domains with paths
  if (trimmed.includes("/")) {
    throw new DomainValidationError(
      "Domain cannot contain paths. Provide a hostname only."
    );
  }

  // Reject domains with ports
  if (trimmed.includes(":")) {
    throw new DomainValidationError(
      "Domain cannot contain ports. Provide a hostname only."
    );
  }

  // Reject localhost (unless allowInsecureRequests is set for dev scenarios)
  if (
    !options?.allowInsecureRequests &&
    (trimmed === "localhost" ||
      trimmed.startsWith("localhost.") ||
      trimmed.endsWith(".localhost"))
  ) {
    throw new DomainValidationError("localhost domains are not supported.");
  }

  // Reject .local domains unconditionally (mDNS, not valid Auth0 domains)
  if (trimmed.endsWith(".local")) {
    throw new DomainValidationError(".local domains are not supported.");
  }

  // Reject IPv4 addresses
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    throw new DomainValidationError("IPv4 addresses are not supported.");
  }

  // IPv6 addresses are implicitly rejected above because they contain colons.
  // The patterns below are kept as legacy documentation but are unreachable:
  // - /^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$/ (generic IPv6)
  // - /^::1$/ (IPv6 loopback)
  // - /^::$/ (IPv6 any address)
  // No separate IPv6 validation needed; port check above handles all cases.
}

/**
 * Options for domain normalization.
 */
interface NormalizeDomainOptions {
  /**
   * An issuer hint to use if the domain cannot be parsed as a URL.
   * Useful for converting bare hostnames to issuer URLs.
   */
  issuerHint?: string;
  /**
   * Allow insecure (HTTP) requests for testing purposes.
   * Default: false
   */
  allowInsecureRequests?: boolean;
}

/**
 * Normalizes a domain value (URL or hostname) and returns both the normalized domain and issuer.
 *
 * Accepts:
 * - Full issuer URLs: "https://example.auth0.com/"
 * - URLs without trailing slash: "https://example.auth0.com"
 * - Bare hostnames: "example.auth0.com"
 *
 * @param value - The domain value to normalize (URL or hostname)
 * @param options - Normalization options
 * @returns An object with normalized domain and issuer
 * @throws {DomainValidationError} If the domain fails validation
 * @throws {IssuerValidationError} If the issuer cannot be constructed
 * @internal
 */
export function normalizeDomain(
  value: string,
  options?: NormalizeDomainOptions
): {
  domain: string;
  issuer: string;
} {
  const trimmed = value.trim();

  let hostname: string;
  let scheme = "https";

  try {
    // Try to parse as a URL (case-insensitive scheme detection)
    const urlLower = trimmed.toLowerCase();
    if (urlLower.startsWith("http://") || urlLower.startsWith("https://")) {
      const url = new URL(trimmed);
      hostname = url.hostname;
      scheme = url.protocol.replace(":", "");

      // Validate that URL has no path, query, or fragment (except trailing slash)
      if (url.pathname !== "/" || url.search || url.hash) {
        throw new DomainValidationError(
          "Domain URL cannot contain path, query, or fragment parameters."
        );
      }
    } else {
      // Treat as bare hostname
      hostname = trimmed;
    }
  } catch (err) {
    if (err instanceof DomainValidationError) {
      throw err;
    }
    // URL parsing failed; treat as bare hostname
    hostname = trimmed;
  }

  // Validate the hostname
  validateDomainHostname(hostname, {
    allowInsecureRequests: options?.allowInsecureRequests
  });

  // Construct the issuer URL
  let issuer: string;
  if (options?.issuerHint) {
    issuer = normalizeIssuer(options.issuerHint);
  } else {
    // Use scheme from parsed URL or default to https
    const protocol = options?.allowInsecureRequests ? scheme : "https";
    issuer = normalizeIssuer(`${protocol}://${hostname}`);
  }

  return {
    domain: hostname,
    issuer
  };
}
