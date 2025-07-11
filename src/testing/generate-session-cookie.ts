import { encrypt } from "../server/cookies.js";
import { SessionData } from "../types/index.js";

export type GenerateSessionCookieConfig = {
  /**
   * The secret used to derive an encryption key for the session cookie.
   *
   * **IMPORTANT**: you must use the same value as in the SDK configuration.
   */
  secret: string;
};

export const generateSessionCookie = async (
  session: Partial<SessionData>,
  config: GenerateSessionCookieConfig
): Promise<string> => {
  if (!("internal" in session)) {
    session.internal = {
      sid: "auth0-sid",
      createdAt: Math.floor(Date.now() / 1000)
    };
  }

  const maxAge = 60 * 60; // 1 hour in seconds
  const expiration = Math.floor(Date.now() / 1000 + maxAge);

  return encrypt(session, config.secret, expiration);
};
