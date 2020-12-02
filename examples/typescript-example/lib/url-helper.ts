export default function createLoginUrl(redirectTo?: string): string {
  if (redirectTo) {
    return `/api/auth/login?redirectTo=${encodeURIComponent(redirectTo)}`;
  }
  return `/api/auth/login`;
}
