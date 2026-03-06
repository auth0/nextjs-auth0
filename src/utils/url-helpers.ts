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
