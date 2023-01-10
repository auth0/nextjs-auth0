import { Config as BaseConfig, CookieConfig, StatelessSession, NodeCookies as Cookies } from '../auth0-session';
import { Session } from '../session';

/**
 * Configuration parameters used by {@link generateSessionCookie}.
 */
export type GenerateSessionCookieConfig = {
  /**
   * The secret used to derive an encryption key for the session cookie.
   *
   * **IMPORTANT**: you must use the same value as in the SDK configuration.
   * See {@link ConfigParameters.secret}.
   */
  secret: string;

  /**
   * Integer value, in seconds, used as the duration of the session cookie.
   * Defaults to `604800` seconds (7 days).
   */
  duration?: number;
} & Partial<CookieConfig>;

export const generateSessionCookie = async (
  session: Partial<Session>,
  config: GenerateSessionCookieConfig
): Promise<string> => {
  const weekInSeconds = 7 * 24 * 60 * 60;
  const { secret, duration: absoluteDuration = weekInSeconds, ...cookie } = config;
  const cookieStoreConfig = { secret, session: { absoluteDuration, cookie } };
  const cookieStore = new StatelessSession(cookieStoreConfig as BaseConfig, Cookies);
  const epoch = (Date.now() / 1000) | 0;
  return cookieStore.encrypt(session, { iat: epoch, uat: epoch, exp: epoch + absoluteDuration });
};
