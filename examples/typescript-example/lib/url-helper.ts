export default function createLoginUrl(redirectTo?: string): string {
  if (redirectTo) {
    return `/api/login?redirectTo=${encodeURIComponent(redirectTo)}`;
  }
  return `/api/login`;
}
