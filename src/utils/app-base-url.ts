import { NextRequest } from "next/server.js";

import { InvalidConfigurationError } from "../errors/index.js";

const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

function ensureHttpUrl(url: URL, label: string) {
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new InvalidConfigurationError(`${label} must use http or https.`);
  }
}

function normalizeBaseUrlString(
  value: string,
  label: string,
  requireHttp = false
): string {
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

  if (requireHttp) {
    ensureHttpUrl(url, label);
  }

  return trimmed;
}

function getFirstHeaderValue(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const [first] = value.split(",");
  return first?.trim() || null;
}

export function inferBaseUrlFromRequest(req: NextRequest): string | null {
  const forwardedProto = getFirstHeaderValue(
    req.headers.get("x-forwarded-proto")
  );
  const forwardedHost = getFirstHeaderValue(
    req.headers.get("x-forwarded-host")
  );
  const host =
    forwardedHost ||
    getFirstHeaderValue(req.headers.get("host")) ||
    req.nextUrl?.host;
  const proto =
    forwardedProto || req.nextUrl?.protocol?.replace(":", "") || undefined;

  if (!host || !proto) {
    return null;
  }

  try {
    return normalizeBaseUrlString(`${proto}://${host}`, "Request host", true);
  } catch {
    return null;
  }
}

export function resolveAppBaseUrl(
  appBaseUrl: string | undefined,
  req?: NextRequest
): string {
  if (appBaseUrl) {
    // Use the configured base URL as-is.
    return appBaseUrl;
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
