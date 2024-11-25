import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { generateSecret } from "../../test/utils"
import { SessionData } from "../../types"
import { decrypt, encrypt, RequestCookies, ResponseCookies } from "../cookies"
import { StatefulSessionStore } from "./stateful-session-store"

describe("Stateful Session Store", async () => {
  describe("get", async () => {
    it("should call the store.get method with the session ID", async () => {
      const sessionId = "ses_123"
      const secret = await generateSecret(32)
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456,
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn(),
      }
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId,
        },
        secret
      )

      const headers = new Headers()
      headers.append("cookie", `__session=${encryptedCookieValue}`)
      const requestCookies = new RequestCookies(headers)

      const sessionStore = new StatefulSessionStore({
        secret,
        store,
      })

      const sessionFromDb = await sessionStore.get(requestCookies)
      expect(store.get).toHaveBeenCalledOnce()
      expect(store.get).toHaveBeenCalledWith(sessionId)
      expect(sessionFromDb).toEqual(session)
    })

    it("should return null if no session cookie exists", async () => {
      const secret = await generateSecret(32)
      const headers = new Headers()
      const requestCookies = new RequestCookies(headers)
      const store = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn(),
      }
      const sessionStore = new StatefulSessionStore({
        secret,
        store,
      })

      expect(await sessionStore.get(requestCookies)).toBeNull()
    })

    it("should return null if no matching session exists in the DB", async () => {
      const sessionId = "ses_does_not_exist"
      const secret = await generateSecret(32)
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456,
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const store = {
        get: vi.fn().mockImplementation(async (sessionId: string) => {
          if (sessionId === "ses_123") {
            return session
          }

          return null
        }),
        set: vi.fn(),
        delete: vi.fn(),
      }
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId,
        },
        secret
      )

      const headers = new Headers()
      headers.append("cookie", `__session=${encryptedCookieValue}`)
      const requestCookies = new RequestCookies(headers)

      const sessionStore = new StatefulSessionStore({
        secret,
        store,
      })

      const sessionFromDb = await sessionStore.get(requestCookies)
      expect(store.get).toHaveBeenCalledOnce()
      expect(store.get).toHaveBeenCalledWith(sessionId)
      expect(sessionFromDb).toBeNull()
    })
  })

  describe("set", async () => {
    describe("with rolling sessions enabled", async () => {
      beforeEach(() => {
        vi.useFakeTimers()
      })

      afterEach(() => {
        vi.restoreAllMocks()
      })

      it("should extend the cookie lifetime by the inactivity duration", async () => {
        const currentTime = Date.now()
        const createdAt = Math.floor(currentTime / 1000)
        const secret = await generateSecret(32)
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
          },
          internal: {
            sid: "auth0-sid",
            createdAt,
          },
        }
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn(),
        }

        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })
        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")
        const cookieValue = await decrypt(cookie!.value, secret)

        expect(cookie).toBeDefined()
        expect(cookieValue).toHaveProperty("id")
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(1800)

        expect(store.set).toHaveBeenCalledOnce()
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session)
      })

      it("should not exceed the absolute timeout duration", async () => {
        const currentTime = Date.now()
        const createdAt = Math.floor(currentTime / 1000)
        const secret = await generateSecret(32)
        const session: SessionData = {
          createdAt,
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
          },
          internal: {
            sid: "auth0-sid",
            createdAt,
          },
        }
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn(),
        }

        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })

        // advance time by 2 hours - session should expire after 1 hour
        vi.setSystemTime(currentTime + 2 * 3600 * 1000)

        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")
        const cookieValue = await decrypt(cookie!.value, secret)

        expect(cookie).toBeDefined()
        expect(cookieValue).toHaveProperty("id")
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(0) // cookie should expire immedcreatedAtely

        expect(store.set).toHaveBeenCalledOnce()
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session)
      })
    })

    describe("with rolling sessions disabled", async () => {
      it("should set the cookie with a maxAge of the absolute session duration and call store.set", async () => {
        const secret = await generateSecret(32)
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000),
          },
        }
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn(),
        }

        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: false,
          absoluteDuration: 3600,
        })
        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")
        const cookieValue = await decrypt(cookie!.value, secret)

        expect(cookie).toBeDefined()
        expect(cookieValue).toHaveProperty("id")
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(3600)

        expect(store.set).toHaveBeenCalledOnce()
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session)
      })
    })

    describe("session fixation", async () => {
      it("should generate a new session ID if the session is new", async () => {
        const sessionId = "ses_123"
        const secret = await generateSecret(32)
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000),
          },
        }
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn(),
        }

        const encryptedCookieValue = await encrypt(
          {
            id: sessionId,
          },
          secret
        )
        const headers = new Headers()
        headers.append("cookie", `__session=${encryptedCookieValue}`)
        const requestCookies = new RequestCookies(headers)
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: false,
          absoluteDuration: 3600,
        })
        await sessionStore.set(requestCookies, responseCookies, session, true)

        const cookie = responseCookies.get("__session")
        const cookieValue = await decrypt(cookie!.value, secret)

        expect(cookie).toBeDefined()
        expect(store.delete).toHaveBeenCalledWith(sessionId) // the old session should be deleted
        expect(store.set).toHaveBeenCalledOnce()
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session) // a new session ID should be generated
      })
    })
  })

  describe("delete", async () => {
    it("should remove the cookie and call store.delete with the session ID", async () => {
      const sessionId = "ses_123"
      const secret = await generateSecret(32)
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456,
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn(),
      }
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId,
        },
        secret
      )
      const headers = new Headers()
      headers.append("cookie", `__session=${encryptedCookieValue}`)
      const requestCookies = new RequestCookies(headers)
      const responseCookies = new ResponseCookies(new Headers())

      const sessionStore = new StatefulSessionStore({
        secret,
        store,
      })
      await sessionStore.set(requestCookies, responseCookies, session)
      expect(responseCookies.get("__session")).toBeDefined()

      await sessionStore.delete(requestCookies, responseCookies)
      const cookie = responseCookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
      expect(store.delete).toHaveBeenCalledOnce()
      expect(store.delete).toHaveBeenCalledWith(sessionId)
    })

    it("should not throw an error if the cookie does not exist", async () => {
      const secret = await generateSecret(32)
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456,
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn(),
      }
      const requestCookies = new RequestCookies(new Headers())
      const responseCookies = new ResponseCookies(new Headers())

      const sessionStore = new StatefulSessionStore({
        secret,
        store,
      })

      await sessionStore.delete(requestCookies, responseCookies)
      const cookie = responseCookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
      expect(store.delete).not.toHaveBeenCalled()
    })
  })
})
