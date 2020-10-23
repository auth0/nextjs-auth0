/**
 * Helper which tests if a URL can safely be redirected to. Requires the URL to be relative.
 * @param url
 */
export default function isSafeRedirect(url: string): boolean {
  if (typeof url !== 'string') {
    throw new TypeError(`Invalid url: ${url}`);
  }

  // Prevent open redirects using the //foo.com format (double forward slash).
  if (/\/\//.test(url)) {
    return false;
  }

  return !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(url);
}
