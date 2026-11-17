import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import { isLoopbackHost } from "./url-helpers.js";

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
  if (url && url.port === "" && value.endsWith(":443")) {
    fail(`domain must not include the default port 443: use "${url.host}".`);
  }
  if (!url || url.host !== value.toLowerCase()) {
    fail(
      `domain must be a bare host such as "fernway.com", without scheme or path, got "${value}".`
    );
  }

  const local = isLoopbackHost(url.hostname);
  if (local && production) {
    fail(
      `domain "${value}" is a local host, which is only allowed outside production. Set it to the public host that serves the app.`
    );
  }
  // The spec includes the port when it isn't 443, and so does `resource`.
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

// The SDK serves whichever version the file names. It only checks the
// `major.minor` form every version shares, since agents ignore a document
// whose version they can't read.
function validateProtocolVersion(value: unknown): string {
  if (typeof value !== "string" || !/^\d+\.\d+$/.test(value)) {
    fail(
      `protocolVersion must be a major.minor version, got ${typeof value === "string" ? `"${value}"` : typeof value}.`
    );
  }
  return value;
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

const SCOPE_HINT_CHANGES = new Set(["none", "reversible", "irreversible"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

// Served as `auth.scope_hints`. The spec requires both fields in each entry.
function validateScopeHints(
  value: unknown
): Record<string, { changes: string; personal_data: boolean }> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isPlainObject(value)) {
    fail("scopeHints must be an object mapping each scope to its hint.");
  }
  const hints: Record<string, { changes: string; personal_data: boolean }> = {};
  for (const [name, hint] of Object.entries(value)) {
    if (
      !isPlainObject(hint) ||
      typeof hint.changes !== "string" ||
      !SCOPE_HINT_CHANGES.has(hint.changes) ||
      typeof hint.personalData !== "boolean"
    ) {
      fail(
        `scope hint "${name}" must have changes ("none", "reversible" or "irreversible") and a boolean personalData.`
      );
    }
    hints[name] = { changes: hint.changes, personal_data: hint.personalData };
  }
  return hints;
}

function validateApis(
  value: unknown
): { type: string; url: string; description: string }[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    fail("apis must be an array.");
  }
  return value.map((api: unknown, index) => {
    if (
      !isPlainObject(api) ||
      !isNonEmptyString(api.type) ||
      !isNonEmptyString(api.description)
    ) {
      fail(`apis[${index}] must have a non-empty type and description.`);
    }
    return {
      type: api.type,
      url: requireHttpsUrl(api.url, `apis[${index}].url`).raw,
      description: api.description
    };
  });
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

  const protocolVersion = validateProtocolVersion(config.protocolVersion);
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
  const scopeHints = validateScopeHints(config.scopeHints);
  const apis = validateApis(config.apis);
  if (config.unscoped !== undefined && typeof config.unscoped !== "boolean") {
    fail("unscoped must be a boolean.");
  }
  if (!isNonEmptyString(config.organizationName)) {
    fail("organizationName must be a non-empty string.");
  }
  const logoUri =
    config.logoUri === undefined
      ? undefined
      : requireHttpsUrl(config.logoUri, "logoUri").raw;

  return {
    poppy: {
      protocol_version: protocolVersion,
      organization: {
        name: config.organizationName,
        domain,
        ...(logoUri !== undefined && { logo_uri: logoUri })
      },
      auth: {
        issuer,
        ...(scopes !== undefined && { scopes }),
        ...(scopeHints !== undefined && { scope_hints: scopeHints })
      },
      ...(apis !== undefined && { apis }),
      web: {
        browser_session_endpoint: browserSessionEndpoint,
        ...(config.unscoped !== undefined && { unscoped: config.unscoped })
      }
    },
    protectedResource: {
      resource: `${local ? "http" : "https"}://${domain}`,
      authorization_servers: [issuer]
    }
  };
}
