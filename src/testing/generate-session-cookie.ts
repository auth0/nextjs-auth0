import { encrypt } from "../server/cookies"
import { SessionData } from "../types"

export type GenerateSessionCookieConfig = {
  /**
   * The secret used to derive an encryption key for the session cookie.
   *
   * **IMPORTANT**: you must use the same value as in the SDK configuration.
   */
  secret: string
}

export const generateSessionCookie = async (
  session: Partial<SessionData>,
  config: GenerateSessionCookieConfig
): Promise<string> => {
  if (!("internal" in session)) {
    session.internal = {
      sid: "auth0-sid",
      createdAt: Math.floor(Date.now() / 1000),
    }
  }

  return encrypt(session, config.secret)
}
