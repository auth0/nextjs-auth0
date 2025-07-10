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
