export interface TokenSet {
  accessToken: string
  refreshToken?: string
  expiresAt: number // the time at which the access token expires in seconds since epoch
}

export interface SessionData {
  user: User
  tokenSet: TokenSet
  internal: {
    // the session ID from the authorization server
    sid: string
    // the time at which the session was created in seconds since epoch
    createdAt: number
  }
  [key: string]: unknown
}

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
