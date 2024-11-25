import type { User } from "../types"

const DEFAULT_ALLOWED_CLAIMS = [
  "sub",
  "name",
  "nickname",
  "given_name",
  "family_name",
  "picture",
  "email",
  "email_verified",
  "org_id",
]

export function filterClaims(claims: { [key: string]: any }) {
  return Object.keys(claims).reduce((acc, key) => {
    if (DEFAULT_ALLOWED_CLAIMS.includes(key)) {
      acc[key] = claims[key]
    }
    return acc
  }, {} as User)
}
