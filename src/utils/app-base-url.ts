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
  appBaseUrl: string | string[] | undefined,
  req?: NextRequest
): string {
  const staticAppBaseUrl =
    typeof appBaseUrl === "string" ? appBaseUrl : undefined;
  const allowedAppBaseUrls =
    typeof appBaseUrl === "string" ? undefined : appBaseUrl;

  if (staticAppBaseUrl) {
    return staticAppBaseUrl;
  }

  // If we do not have a request, we can not resolve the base URL.
  if (!req) {
    throw new InvalidConfigurationError(
      "APP_BASE_URL is not configured as a static string, and a request context is not available."
    );
  }

  // Resolve the request origin, then validate it against the allow list.
  const inferred = inferBaseUrlFromRequest(req);
  if (!inferred) {
    throw new InvalidConfigurationError(
      "APP_BASE_URL is not configured as a static string, and the request origin could not be determined from the request context. "
    );
  }

  if (!allowedAppBaseUrls) {
    return inferred;
  }

  const requestOrigin = new URL(inferred).origin;

  const isRequestOriginAllowed = allowedAppBaseUrls.some((allowedUrl) => {
    try {
      return new URL(allowedUrl).origin === requestOrigin;
    } catch {
      return false;
    }
  });

  if (isRequestOriginAllowed) {
    return requestOrigin;
  }

  throw new InvalidConfigurationError(
    `APP_BASE_URL is not configured as a static string, and the APP_BASE_URL configuration does not contain a match for the current request origin.`
  );
}
