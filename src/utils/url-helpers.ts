/**
 * Helper which tests if a URL can safely be redirected to. Requires the URL to be relative.
 * @param url
 */
export function isSafeRedirect(url: string): boolean {
  if (typeof url !== 'string') {
    throw new TypeError(`Invalid url: ${url}`);
  }

  // Prevent open redirects using the //foo.com format (double forward slash).
  if (/\/\//.test(url)) {
    return false;
  }

  return !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(url);
}

/**
 * Helper which creates the login URL to redirect to.
 * @param redirectTo
 */
export function createLoginUrl(redirectTo?: string): string {
  if (redirectTo) {
    return `/api/login?redirectTo=${encodeURIComponent(redirectTo)}`;
  }

  return `/api/login`;
}
