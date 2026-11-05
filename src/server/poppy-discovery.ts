import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import { POPPY_PROTOCOL_VERSION } from "../utils/poppy-constants.js";
import { isLoopbackHost } from "../utils/url-helpers.js";

/** The two discovery documents, built once from {@link PoppyConfig}. */
export interface PoppyDiscoveryDocuments {
  poppy: Record<string, unknown>;
  protectedResource: Record<string, unknown>;
}

function fail(message: string): never {
  throw new InvalidConfigurationError(`Invalid poppy.config: ${message}`);
}

// Returns the value as written, so the served documents carry exactly what
// the config says. URL#toString() would normalize it.
function requireHttpsUrl(
  value: unknown,
  field: string
): { raw: string; url: URL } {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${field} must be a non-empty string.`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(`${field} must be a valid URL, got "${value}".`);
  }
  if (url.protocol !== "https:") {
    fail(`${field} must use https, got "${value}".`);
  }
  return { raw: value, url };
}

function validateDomain(
  value: unknown,
  production: boolean
): { domain: string; local: boolean } {
  if (typeof value !== "string" || value.length === 0) {
    fail("domain must be a non-empty string.");
  }
  // A host (with an optional port) round-trips through URL unchanged; anything
  // with a scheme, path or credentials does not.
  let url: URL | undefined;
  try {
    url = new URL(`https://${value}`);
  } catch {
    url = undefined;
  }
  if (!url || url.host !== value.toLowerCase()) {
    fail(
      `domain must be a bare host such as "fernway.com", without scheme, port or path, got "${value}".`
    );
  }

  const local = isLoopbackHost(url.hostname);
  if (local && production) {
    fail(
      `domain "${value}" is a local host, which is only allowed outside production. Set it to the public host that serves the app.`
    );
  }
  // The spec forbids a port. Local mode allows one, to match `next dev`.
  if (url.port && !local) {
    fail(
      `domain must be a bare host such as "fernway.com", without scheme, port or path, got "${value}".`
    );
  }
  return { domain: url.host, local };
}

function validateIssuer(value: unknown): string {
  const { raw, url } = requireHttpsUrl(value, "issuer");
  if (url.search || url.hash) {
    fail(`issuer must not have a query or fragment, got "${raw}".`);
  }
  // Agents compare the issuer character for character, and Auth0's ends with
  // a slash. A missing slash is the most common mismatch.
  if (!raw.endsWith("/")) {
    fail(
      `issuer must match Auth0's issuer exactly, including the trailing slash: use "${raw}/".`
    );
  }
  return raw;
}

function validateScopes(value: unknown): Record<string, string> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("scopes must be an object mapping each scope to its description.");
  }
  const scopes: Record<string, string> = {};
  for (const [name, description] of Object.entries(value)) {
    if (typeof description !== "string" || description.trim().length === 0) {
      fail(`scope "${name}" must have a non-empty description.`);
    }
    scopes[name] = description;
  }
  return scopes;
}

/**
 * Validates `poppy.config` and builds `/.well-known/poppy.json` and
 * `/.well-known/oauth-protected-resource` from it.
 *
 * Throws {@link InvalidConfigurationError} on an invalid config, so a broken
 * file fails at startup instead of being served to agents, which reject a
 * mismatched document without reporting it.
 *
 * Local mode: outside production, a loopback `domain` (`localhost`,
 * `*.localhost`, `127.0.0.1`, `[::1]`) may include a port, and `resource` uses
 * http, so the files match what `next dev` serves. In production a loopback
 * `domain` throws.
 */
export function buildPoppyDiscoveryDocuments(
  config: PoppyConfig,
  options: { production?: boolean } = {}
): PoppyDiscoveryDocuments {
  if (typeof config !== "object" || config === null) {
    fail("expected the contents of auth0-poppy.json.");
  }

  const production =
    options.production ??
    (typeof process !== "undefined" && process.env?.NODE_ENV === "production");

  if (config.protocolVersion !== POPPY_PROTOCOL_VERSION) {
    fail(
      `protocolVersion "${config.protocolVersion}" is not supported. This SDK supports "${POPPY_PROTOCOL_VERSION}".`
    );
  }

  const { domain, local } = validateDomain(config.domain, production);
  if (local) {
    console.warn(
      `[nextjs-auth0] Poppy local mode: serving discovery files for "${domain}" with an http resource. Personal Agents require a public HTTPS host, so use this for local testing only.`
    );
  }
  const issuer = validateIssuer(config.issuer);
  const browserSessionEndpoint = requireHttpsUrl(
    config.browserSessionEndpoint,
    "browserSessionEndpoint"
  ).raw;
  const scopes = validateScopes(config.scopes);

  if (
    config.organizationName !== undefined &&
    (typeof config.organizationName !== "string" ||
      config.organizationName.trim().length === 0)
  ) {
    fail("organizationName must be a non-empty string.");
  }
  const logoUri =
    config.logoUri === undefined
      ? undefined
      : requireHttpsUrl(config.logoUri, "logoUri").raw;

  return {
    poppy: {
      protocol_version: POPPY_PROTOCOL_VERSION,
      organization: {
        ...(config.organizationName !== undefined && {
          name: config.organizationName
        }),
        domain,
        ...(logoUri !== undefined && { logo_uri: logoUri })
      },
      auth: {
        issuer,
        ...(scopes !== undefined && { scopes })
      },
      web: {
        browser_session_endpoint: browserSessionEndpoint
      }
    },
    protectedResource: {
      resource: `${local ? "http" : "https"}://${domain}`,
      authorization_servers: [issuer]
    }
  };
}
