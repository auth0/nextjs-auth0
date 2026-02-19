import { NextRequest } from "next/server.js";

import { InvalidConfigurationError } from "../errors/index.js";

export type AppBaseUrlInput = string | string[] | undefined;

const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

function ensureHttpUrl(url: URL, label: string) {
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new InvalidConfigurationError(`${label} must use http or https.`);
  }
}

function normalizeBaseUrlString(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new InvalidConfigurationError(`${label} must be a non-empty URL.`);
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new InvalidConfigurationError(`${label} must be an absolute URL.`);
  }

  ensureHttpUrl(url, label);
  url.hash = "";
  url.search = "";

  return url.toString().replace(/\/$/, "");
}

function normalizeBaseUrlValues(values: unknown[], label: string) {
  const normalized = values
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => normalizeBaseUrlString(value, label));

  return normalized.length > 0 ? normalized : undefined;
}

function firstHeaderValue(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const [first] = value.split(",");
  return first?.trim() || null;
}

export function normalizeAppBaseUrlConfig(
  input: AppBaseUrlInput,
  envValue?: string
): string[] | undefined {
  if (input !== undefined) {
    if (Array.isArray(input)) {
      return normalizeBaseUrlValues(input, "appBaseUrl");
    }

    if (typeof input === "string" && input.includes(",")) {
      const splitValues = input
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0);

      return normalizeBaseUrlValues(splitValues, "appBaseUrl");
    }

    if (typeof input === "string") {
      return [normalizeBaseUrlString(input, "appBaseUrl")];
    }

    return normalizeBaseUrlValues([input], "appBaseUrl");
  }

  if (!envValue) {
    return undefined;
  }

  const envValues = envValue
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);

  return normalizeBaseUrlValues(envValues, "APP_BASE_URL");
}

export function inferBaseUrlFromRequest(req: NextRequest): string | null {
  const forwardedProto = firstHeaderValue(req.headers.get("x-forwarded-proto"));
  const forwardedHost = firstHeaderValue(req.headers.get("x-forwarded-host"));
  const host =
    forwardedHost ||
    firstHeaderValue(req.headers.get("host")) ||
    req.nextUrl?.host;
  const proto =
    forwardedProto || req.nextUrl?.protocol?.replace(":", "") || undefined;

  if (!host || !proto) {
    return null;
  }

  try {
    return normalizeBaseUrlString(`${proto}://${host}`, "Request host");
  } catch {
    return null;
  }
}

export function matchAppBaseUrlForRequest(
  appBaseUrls: string[],
  requestBaseUrl: string,
  requestPathname?: string
): string | undefined {
  // Resolve the request origin/path once to compare against allow-list entries.
  const requestOrigin = new URL(requestBaseUrl).origin;
  const requestPath = requestPathname || "/";

  const matches = appBaseUrls.filter((baseUrl) => {
    const parsed = new URL(baseUrl);
    // Origin mismatch means this entry is not a candidate.
    if (parsed.origin !== requestOrigin) {
      return false;
    }

    // Allow root (or empty) paths to match any request path on the same origin.
    const basePath = parsed.pathname.replace(/\/$/, "");
    if (!basePath || basePath === "/") {
      return true;
    }

    // Otherwise, require an exact path match or a deeper path under the base path.
    return requestPath === basePath || requestPath.startsWith(`${basePath}/`);
  });

  if (matches.length === 0) {
    return undefined;
  }

  // Pick the most specific path when multiple entries match.
  return matches.sort(
    (a, b) => new URL(b).pathname.length - new URL(a).pathname.length
  )[0];
}

export function resolveAppBaseUrl(
  appBaseUrls: string[] | undefined,
  isStaticAppBaseUrl: boolean,
  req?: NextRequest
): string {
  if (appBaseUrls?.length) {
    // Static appBaseUrl (single string) is authoritative; no host matching needed.
    if (isStaticAppBaseUrl) {
      return appBaseUrls[0];
    }

    if (!req) {
      // Without a request we cannot validate host/path, so only a single allow-list entry is resolvable.
      if (appBaseUrls.length === 1) {
        return appBaseUrls[0];
      }

      throw new InvalidConfigurationError(
        "Multiple appBaseUrl values are configured. Provide a request to resolve the matching host."
      );
    }

    // Resolve the host from request headers and validate against the allow list.
    const inferred = inferBaseUrlFromRequest(req);
    if (!inferred) {
      throw new InvalidConfigurationError(
        "Unable to resolve appBaseUrl from request headers. Set appBaseUrl/APP_BASE_URL or ensure the request host is available."
      );
    }

    // Prefer the most specific allow-list entry when multiple match.
    const match = matchAppBaseUrlForRequest(
      appBaseUrls,
      inferred,
      req.nextUrl?.pathname
    );

    if (!match) {
      throw new InvalidConfigurationError(
        `The request origin "${inferred}" is not in the configured appBaseUrl allow list.`
      );
    }

    return match;
  }

  if (req) {
    // No configured appBaseUrl: infer from request headers as a dynamic base URL fallback.
    // In this case, Auth0 Allowed Callback URLs provide the primary host safeguard.
    const inferred = inferBaseUrlFromRequest(req);
    if (inferred) {
      return inferred;
    }
  }

  throw new InvalidConfigurationError(
    "appBaseUrl could not be resolved. Set appBaseUrl/APP_BASE_URL or ensure the request host is available."
  );
}
