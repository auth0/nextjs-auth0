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
    fail("organization.domain must be a non-empty string.");
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
    fail(
      `organization.domain must not include the default port 443: use "${url.host}".`
    );
  }
  // An internationalized name must be written in its ASCII (punycode) form,
  // which is what agents compare with.
  if (url && [...value].some((c) => c.charCodeAt(0) > 0x7f)) {
    fail(
      `organization.domain must be in its ASCII (punycode) form: use "${url.host}".`
    );
  }
  if (!url || url.host !== value.toLowerCase()) {
    fail(
      `organization.domain must be a bare host such as "fernway.com", without scheme or path, got "${value}".`
    );
  }
  // poppy.json is served as written, and agents compare it character for
  // character with the resource, which is lowercase.
  if (value !== url.host) {
    fail(`organization.domain must be lowercase: use "${url.host}".`);
  }

  const local = isLoopbackHost(url.hostname);
  if (local && production) {
    fail(
      `organization.domain "${value}" is a local host, which is only allowed outside production. Set it to the public host that serves the app.`
    );
  }
  // The spec includes the port when it isn't 443, and so does `resource`.
  return { domain: url.host, local };
}

function validateIssuer(value: unknown): string {
  const { raw, url } = requireHttpsUrl(value, "auth.issuer");
  if (url.search || url.hash) {
    fail(`auth.issuer must not have a query or fragment, got "${raw}".`);
  }
  // Agents compare the issuer character for character, and Auth0's ends with
  // a slash. A missing slash is the most common mismatch.
  if (!raw.endsWith("/")) {
    fail(
      `auth.issuer must match Auth0's issuer exactly, including the trailing slash: use "${raw}/".`
    );
  }
  // Agents compare the issuer character for character with Auth0's, which is
  // `https://<host>/` in canonical form: lowercase, no default port, no path.
  if (url.href !== raw || url.pathname !== "/") {
    fail(
      `auth.issuer must match Auth0's issuer exactly, such as "${url.origin}/", got "${raw}".`
    );
  }
  return raw;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Builds `/.well-known/poppy.json` and `/.well-known/oauth-protected-resource`
 * from `poppy.config`, the `poppy.json` written by `auth0 poppy config`.
 *
 * `poppy.json` is served as written. Only the two values the SDK uses are
 * checked: `organization.domain`, which names the protected resource, and
 * `auth.issuer`, which lists the authorization server and is matched against
 * a browser join's `iss`. A bad value throws {@link InvalidConfigurationError}
 * at startup. `auth0 poppy doctor` checks the rest of the file.
 *
 * Local mode: outside production, a loopback `organization.domain`
 * (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`) may include a port, and
 * `resource` uses http, so the files match what `next dev` serves. In
 * production a loopback domain throws.
 */
export function buildPoppyDiscoveryDocuments(
  config: PoppyConfig,
  options: { production?: boolean } = {}
): PoppyDiscoveryDocuments {
  if (
    !isObject(config) ||
    !isObject(config.organization) ||
    !isObject(config.auth)
  ) {
    fail(
      "expected the poppy.json written by auth0 poppy config, with organization and auth objects."
    );
  }

  const production =
    options.production ??
    (typeof process !== "undefined" && process.env?.NODE_ENV === "production");

  const { domain, local } = validateDomain(
    config.organization.domain,
    production
  );
  if (local) {
    console.warn(
      `[nextjs-auth0] Poppy local mode: serving discovery files for "${domain}" with an http resource. Personal Agents require a public HTTPS host, so use this for local testing only.`
    );
  }
  const issuer = validateIssuer(config.auth.issuer);

  return {
    poppy: config,
    protectedResource: {
      resource: `${local ? "http" : "https"}://${domain}`,
      authorization_servers: [issuer]
    }
  };
}
