export default function createLoginURL(loginPath = '/api/login', redirectTo?: string): string {
  return redirectTo != null
    ? `${loginPath}?redirectTo=${encodeURIComponent(redirectTo)}`
    : loginPath
}
