import { Config as BaseConfig, StatelessSession, NodeCookies as Cookies } from '../auth0-session';
import { Session } from '../session';
import { GenerateSessionCookieConfig } from '../../testing';

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
