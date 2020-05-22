/* eslint-disable prettier/prettier */
export default function createLoginURL(loginPath: string, redirectTo?: string): string {
  return redirectTo != null
    ? `${loginPath}?redirectTo=${encodeURIComponent(redirectTo)}`
    : loginPath;
}
