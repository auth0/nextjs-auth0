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
