import type { SessionData, SessionDataStore } from "../../types"
import {
  CookieOptions,
  decrypt,
  encrypt,
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies,
} from "../cookies"

export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__session`.
   */
  name?: string
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none"
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean
}

export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds..
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions
}

interface SessionStoreOptions extends SessionConfiguration {
  secret: string
  store?: SessionDataStore

  cookieOptions?: SessionCookieOptions
}

const SESSION_COOKIE_NAME = "__session"

/**
 * AbstractSessionStore serves as an abstract base class for managing session storage.
 * It defines essential properties and methods that any session store implementation must provide.
 */
export abstract class AbstractSessionStore {
  /**
   * A secret key used for encrypting session data.
   */
  public secret: string

  /**
   * The name of the cookie used to store the session identifier.
   */
  public sessionCookieName: string

  /**
   * Indicates whether the session should be refreshed on each request.
   * Default is true, meaning the session will be extended with each request.
   */
  private readonly rolling: boolean

  /**
   * The maximum duration (in seconds) a session can last, regardless of activity.
   * Default is 3 days (259200 seconds).
   */
  private readonly absoluteDuration: number

  /**
   * The duration (in seconds) after which a session will expire if there is no activity.
   * Default is 1 day (86400 seconds).
   */
  private readonly inactivityDuration: number

  /**
   * An optional reference to a specific session data store implementation.
   */
  public store?: SessionDataStore

  /**
   * Configuration options for the session cookie, including security settings.
   */
  public cookieConfig: CookieOptions

  /**
   * Constructor to initialize an instance of AbstractSessionStore.
   *
   * @param {SessionStoreOptions} options - Configuration options for the session store.
   */
  constructor({
    secret,
    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 3, // Default: 3 days in seconds
    inactivityDuration = 60 * 60 * 24 * 1, // Default: 1 day in seconds
    store,
    cookieOptions,
  }: SessionStoreOptions) {
    this.secret = secret // Set the secret key for encryption

    this.rolling = rolling // Set whether the session is rolling
    this.absoluteDuration = absoluteDuration // Set absolute duration
    this.inactivityDuration = inactivityDuration // Set inactivity duration
    this.store = store // Set the optional session data store

    // Set up cookie configuration with defaults and provided options
    this.sessionCookieName = cookieOptions?.name ?? SESSION_COOKIE_NAME
    this.cookieConfig = {
      httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
      sameSite: cookieOptions?.sameSite ?? "lax", // CSRF protection setting
      secure: cookieOptions?.secure ?? false, // Use secure cookies if true (HTTPS)
      path: "/", // Cookie is valid for all paths
    }
  }

  /**
   * Retrieves the session data based on the provided request cookies.
   *
   * @param {RequestCookies | ReadonlyRequestCookies} reqCookies - Cookies from the request.
   * @returns {Promise<SessionData | null>} - A promise that resolves to the session data or null if no session exists.
   */
  abstract get(
    reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null>

  /**
   * Saves the encrypted session cookie as a `Set-Cookie` header in the response.
   * If the `iat` (issued at) property is present in the session, it will be used to compute the `maxAge` cookie value.
   *
   * @param {RequestCookies | ReadonlyRequestCookies} reqCookies - Cookies from the request.
   * @param {ResponseCookies} resCookies - Cookies to be sent in the response.
   * @param {SessionData} session - The session data to be saved.
   * @param {boolean} [isNew=false] - Indicates if this is a new session. Defaults to false.
   * @returns {Promise<void>} - A promise that resolves when the operation is complete.
   */
  abstract set(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies,
    session: SessionData,
    isNew?: boolean
  ): Promise<void>

  /**
   * Deletes the session based on the provided request cookies and updates response cookies accordingly.
   *
   * @param {RequestCookies | ReadonlyRequestCookies} reqCookies - Cookies from the request.
   * @param {ResponseCookies} resCookies - Cookies to be sent in the response after deletion.
   * @returns {Promise<void>} - A promise that resolves when the operation is complete.
   */
  abstract delete(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies
  ): Promise<void>

  /**
   * Returns the current time in seconds since the Unix epoch (January 1, 1970).
   *
   * @returns {number} - The current time in seconds since epoch.
   */
  epoch() {
    return (Date.now() / 1000) | 0 // Convert milliseconds to seconds and floor it to an integer
  }

  /**
   * Calculates the maximum age of the session based on its creation time,
   * considering both rolling and absolute durations.
   *
   * @param {number} createdAt - The timestamp when the session was created (in seconds).
   * @returns {number} - The maximum age of the session in seconds or zero if expired.
   */
  calculateMaxAge(createdAt: number) {
    if (!this.rolling) {
      return this.absoluteDuration // Return absolute duration if not rolling
    }

    const updatedAt = this.epoch() // Get current time
    const expiresAt = Math.min(
      updatedAt + this.inactivityDuration, // Time after inactivity duration
      createdAt + this.absoluteDuration // Time after absolute duration
    )

    const maxAge = expiresAt - this.epoch() // Calculate max age based on expiration time

    return maxAge > 0 ? maxAge : 0 // Return max age or zero if expired
  }
}
