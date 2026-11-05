export function toSafeRedirect(
  dangerousRedirect: string,
  safeBaseUrl: URL
): URL | undefined {
  let url: URL;

  try {
    url = new URL(dangerousRedirect, safeBaseUrl);
  } catch (e) {
    return undefined;
  }

  if (url.origin === safeBaseUrl.origin) {
    return url;
  }

  return undefined;
}

/**
 * Checks if a string is a valid HTTP or HTTPS URL.
 * @param url The string to check.
 * @returns True if the string is a valid http/https URL, false otherwise.
 */
export function isUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Checks if a hostname is a loopback host: `localhost`, a `*.localhost` name,
 * `127.0.0.1` or `[::1]`. Pass `URL#hostname`, so an IPv6 address keeps its
 * brackets.
 * @param hostname The hostname to check, without a port.
 * @returns True if the hostname is a loopback host.
 */
export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]"
  );
}
