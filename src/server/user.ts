// TODO: allow a developer to define their own user interface
// since it can be overridden. Same for the session data interface.
export interface User {
  sub: string
  name?: string
  nickname?: string
  given_name?: string
  family_name?: string
  picture?: string
  email?: string
  email_verified?: boolean
  org_id?: string

  [key: string]: any
}

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
