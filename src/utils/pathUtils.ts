import { InvalidConfigurationError } from "../errors/index.js";

export function ensureLeadingSlash(value: string) {
  return value && !value.startsWith("/") ? `/${value}` : value;
}

export function ensureTrailingSlash(value: string) {
  return value && !value.endsWith("/") ? `${value}/` : value;
}

export function ensureNoLeadingSlash(value: string) {
  return value && value.startsWith("/")
    ? value.substring(1, value.length)
    : value;
}

export const removeTrailingSlash = (path: string) =>
  path.endsWith("/") ? path.slice(0, -1) : path;

/**
 * Creates a fully-qualified URL by combining a route path with a base URL.
 * Normalizes the path with the application's base path and ensures proper slash handling.
 * @returns fully-qualified URL object
 * @param path The route path (e.g., "/auth/login")
 * @param baseUrl The base URL (e.g., "https://myapp.example.com")
 * @returns A URL object representing the full route URL
 * @throws Error if baseUrl is not provided
 */
export function createRouteUrl(path: string, baseUrl?: string): URL {
  if (!baseUrl) {
    throw new InvalidConfigurationError(
      "appBaseUrl is required for this operation. Provide it in Auth0ClientOptions or ensure it can be resolved from request headers."
    );
  }
  return new URL(
    ensureNoLeadingSlash(normalizeWithBasePath(path)),
    ensureTrailingSlash(baseUrl)
  );
}

export const normalizeWithBasePath = (path: string) => {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH;

  if (!basePath) {
    return path;
  }

  // basePath can be `docs` or `/docs`
  const sanitizedBasePath = ensureLeadingSlash(basePath);

  return ensureTrailingSlash(sanitizedBasePath) + ensureNoLeadingSlash(path);
};
