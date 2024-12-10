import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { generateSecret } from "../../test/utils"
import { SessionData } from "../../types"
import { decrypt, encrypt, RequestCookies, ResponseCookies } from "../cookies"
import { StatelessSessionStore } from "./stateless-session-store"

describe("Stateless Session Store", async () => {
  describe("get", async () => {
    it("should return the decrypted session cookie if it exists", async () => {
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
      const encryptedCookieValue = await encrypt(session, secret)

      const headers = new Headers()
      headers.append("cookie", `__session=${encryptedCookieValue}`)
      const requestCookies = new RequestCookies(headers)

      const sessionStore = new StatelessSessionStore({
        secret,
      })

      expect(await sessionStore.get(requestCookies)).toEqual(session)
    })

    it("should return null if no session cookie exists", async () => {
      const secret = await generateSecret(32)
      const headers = new Headers()
      const requestCookies = new RequestCookies(headers)

      const sessionStore = new StatelessSessionStore({
        secret,
      })

      expect(await sessionStore.get(requestCookies)).toBeNull()
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
        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })

        // advance time by 10 minutes
        vi.setSystemTime(currentTime + 10 * 60 * 1000)

        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")

        expect(cookie).toBeDefined()
        expect(await decrypt(cookie!.value, secret)).toEqual(session)
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(1800) // should be extended by inactivity duration
        expect(cookie?.secure).toEqual(false)
      })

      it("should not exceed the absolute timeout duration", async () => {
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
        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 3600, // 1 hour
          inactivityDuration: 1800, // 30 minutes
        })

        // advance time by 2 hours - session should expire after 1 hour
        vi.setSystemTime(currentTime + 2 * 3600 * 1000)

        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")

        expect(cookie).toBeDefined()
        expect(await decrypt(cookie!.value, secret)).toEqual(session)
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(0) // cookie should expire immediately
        expect(cookie?.secure).toEqual(false)
      })
    })

    describe("with rolling sessions disabled", async () => {
      it("should set the cookie with a maxAge of the absolute session duration", async () => {
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
        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600,
        })
        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")

        expect(cookie).toBeDefined()
        expect(await decrypt(cookie!.value, secret)).toEqual(session)
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(3600)
        expect(cookie?.secure).toEqual(false)
      })
    })

    describe("with cookieOptions", async () => {
      it("should apply the secure attribute to the cookie", async () => {
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
        const requestCookies = new RequestCookies(new Headers())
        const responseCookies = new ResponseCookies(new Headers())

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600,
          cookieOptions: {
            secure: true,
          },
        })
        await sessionStore.set(requestCookies, responseCookies, session)

        const cookie = responseCookies.get("__session")

        expect(cookie).toBeDefined()
        expect(await decrypt(cookie!.value, secret)).toEqual(session)
        expect(cookie?.path).toEqual("/")
        expect(cookie?.httpOnly).toEqual(true)
        expect(cookie?.sameSite).toEqual("lax")
        expect(cookie?.maxAge).toEqual(3600)
        expect(cookie?.secure).toEqual(true)
      })
    })
  })

  describe("delete", async () => {
    it("should remove the cookie", async () => {
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
      const requestCookies = new RequestCookies(new Headers())
      const responseCookies = new ResponseCookies(new Headers())

      const sessionStore = new StatelessSessionStore({
        secret,
      })
      await sessionStore.set(requestCookies, responseCookies, session)
      expect(responseCookies.get("__session")).toBeDefined()

      await sessionStore.delete(requestCookies, responseCookies)
      const cookie = responseCookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
    })

    it("should not throw an error if the cookie does not exist", async () => {
      const secret = await generateSecret(32)
      const requestCookies = new RequestCookies(new Headers())
      const responseCookies = new ResponseCookies(new Headers())
      const sessionStore = new StatelessSessionStore({
        secret,
      })

      expect(
        sessionStore.delete(requestCookies, responseCookies)
      ).resolves.not.toThrow()
    })
  })
})
