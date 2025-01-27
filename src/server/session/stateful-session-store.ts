import { SessionData, SessionDataStore } from "../../types"
import * as cookies from "../cookies"
import { AbstractSessionStore } from "./abstract-session-store"

// the value of the stateful session cookie containing a unique session ID to identify
// the current session
interface SessionCookieValue {
  id: string
}

interface StatefulSessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 3 days
  inactivityDuration?: number // defaults to 1 day

  store: SessionDataStore

  cookieOptions?: Partial<Pick<cookies.CookieOptions, "secure">>
}

const generateId = () => {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

export class StatefulSessionStore extends AbstractSessionStore {
  public store: SessionDataStore

  constructor({
    secret,
    store,
    rolling,
    absoluteDuration,
    inactivityDuration,
    cookieOptions,
  }: StatefulSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
      cookieOptions,
    })

    this.store = store
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    const { id } = await cookies.decrypt<SessionCookieValue>(
      cookieValue,
      this.secret
    )

    return this.store.get(id)
  }

  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData,
    isNew: boolean = false
  ) {
    // check if a session already exists. If so, maintain the existing session ID
    let sessionId = null
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value
    if (cookieValue) {
      const sessionCookie = await cookies.decrypt<SessionCookieValue>(
        cookieValue,
        this.secret
      )
      sessionId = sessionCookie.id
    }

    // if this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session ID to prevent session fixation.
    if (sessionId && isNew) {
      await this.store.delete(sessionId)
      sessionId = generateId()
    }

    if (!sessionId) {
      sessionId = generateId()
    }

    const jwe = await cookies.encrypt(
      {
        id: sessionId,
      },
      this.secret
    )
    const maxAge = this.calculateMaxAge(session.internal.createdAt)

    resCookies.set(this.SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
    await this.store.set(sessionId, session)

    // to enable read-after-write in the same request for middleware
    reqCookies.set(this.SESSION_COOKIE_NAME, jwe.toString())
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value
    await resCookies.delete(this.SESSION_COOKIE_NAME)

    if (!cookieValue) {
      return
    }

    const { id } = await cookies.decrypt<SessionCookieValue>(
      cookieValue,
      this.secret
    )

    await this.store.delete(id)
  }
}
