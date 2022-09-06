/**
 * Helper which tests if a URL can safely be redirected to. Requires the URL to be relative.
 *
 * @param dangerousRedirect
 * @param safeBaseUrl
 */
export default function toSafeRedirect(dangerousRedirect: string, safeBaseUrl: URL): string | undefined {
  let url: URL;
  try {
    url = new URL(dangerousRedirect, safeBaseUrl);
  } catch (e) {
    return undefined;
  }
  if (url.origin === safeBaseUrl.origin) {
    return url.toString();
  }
  return undefined;
}
