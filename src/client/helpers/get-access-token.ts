export async function getAccessToken() {
  // TODO: cache response and invalidate according to expiresAt
  const tokenRes = await fetch("/auth/access-token").then((res) => res.json())

  return tokenRes.token
}
