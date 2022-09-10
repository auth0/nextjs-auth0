import { Config as BaseConfig, CookieStore } from '../auth0-session';
import { CookieConfig } from '../config';
import { Session } from '../session';

/**
 * Configuration parameters used by ({@link generateSessionCookie}.
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

/**
 * Generates an encrypted session cookie that can be used to mock the Auth0
 * authentication flow in e2e tests.
 *
 * **IMPORTANT**: this utility can only run in Node.js, **not in the browser**.
 * For example, if you're using [Cypress](https://www.cypress.io/), you can
 * wrap it in a [task](https://docs.cypress.io/api/commands/task) and then
 * invoke the task from a test or a custom command.
 *
 * @param {Session} session The user's session.
 * @param {GenerateSessionCookieConfig} config Configuration parameters for the session cookie.
 * @return {String}
 */
export const generateSessionCookie = async (
  session: Partial<Session>,
  config: GenerateSessionCookieConfig
): Promise<string> => {
  const weekInSeconds = 7 * 24 * 60 * 60;
  const { secret, duration: absoluteDuration = weekInSeconds, ...cookie } = config;
  const cookieStoreConfig = { secret, session: { absoluteDuration, cookie } };
  const cookieStore = new CookieStore(cookieStoreConfig as BaseConfig);
  const epoch = (Date.now() / 1000) | 0;
  return cookieStore.encrypt(session, { iat: epoch, uat: epoch, exp: epoch + absoluteDuration });
};
