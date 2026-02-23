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
 * Checks if a string is a valid URL.
 * @param url The string to check.
 * @returns True if the string is a valid URL, false otherwise.
 */
export function isUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
