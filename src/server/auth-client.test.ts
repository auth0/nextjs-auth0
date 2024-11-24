import { NextRequest, NextResponse } from "next/server"
import * as jose from "jose"
import * as oauth from "oauth4webapi"
import { describe, expect, it, vi } from "vitest"

import { generateSecret } from "../test/utils"
import { SessionData } from "../types"
import { AuthClient } from "./auth-client"
import { decrypt, encrypt } from "./cookies"
import { StatefulSessionStore } from "./session/stateful-session-store"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { TransactionState, TransactionStore } from "./transaction-store"

describe("Authentication Client", async () => {
  const DEFAULT = {
    domain: "guabu.us.auth0.com",
    clientId: "client_123",
    clientSecret: "client-secret",
    appBaseUrl: "https://example.com",
    sid: "auth0-sid",
    accessToken: "at_123",
    refreshToken: "rt_123",
    sub: "user_123",
    alg: "RS256",
    keyPair: await jose.generateKeyPair("RS256"),
  }

  function getMockAuthorizationServer({
    tokenEndpointResponse,
    discoveryResponse,
    audience,
    nonce,
    keyPair = DEFAULT.keyPair,
  }: {
    tokenEndpointResponse?: oauth.TokenEndpointResponse | oauth.OAuth2Error
    discoveryResponse?: Response
    audience?: string
    nonce?: string
    keyPair?: jose.GenerateKeyPairResult<jose.KeyLike>
  } = {}) {
    // this function acts as a mock authorization server
    return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      let url: URL
      if (input instanceof Request) {
        url = new URL(input.url)
      } else {
        url = new URL(input)
      }

      if (url.pathname === "/oauth/token") {
        const jwt = await new jose.SignJWT({
          sid: DEFAULT.sid,
          auth_time: Date.now(),
          nonce: nonce ?? "nonce-value",
          "https://example.com/custom_claim": "value",
        })
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject(DEFAULT.sub)
          .setIssuedAt()
          .setIssuer(_authorizationServerMetadata.issuer)
          .setAudience(audience ?? DEFAULT.clientId)
          .setExpirationTime("2h")
          .sign(keyPair.privateKey)

        return Response.json(
          tokenEndpointResponse ?? {
            token_type: "Bearer",
            access_token: DEFAULT.accessToken,
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            expires_in: 86400, // expires in 10 days
          }
        )
      }

      // discovery URL
      if (url.pathname === "/.well-known/openid-configuration") {
        return discoveryResponse ?? Response.json(_authorizationServerMetadata)
      }

      return new Response(null, { status: 404 })
    })
  }

  async function generateLogoutToken({
    claims = {},
    audience = DEFAULT.clientId,
    issuer = _authorizationServerMetadata.issuer,
    alg = DEFAULT.alg,

    privateKey = DEFAULT.keyPair.privateKey,
  }: {
    claims?: any
    audience?: string
    issuer?: string
    alg?: string
    privateKey?: jose.KeyLike
  }): Promise<string> {
    return await new jose.SignJWT({
      events: {
        "http://schemas.openid.net/event/backchannel-logout": {},
      },
      sub: DEFAULT.sub,
      sid: DEFAULT.sid,
      ...claims,
    })
      .setProtectedHeader({ alg, typ: "logout+jwt" })
      .setIssuedAt()
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime("2h")
      .setJti("some-jti")
      .sign(privateKey)
  }

  async function getCachedJWKS(): Promise<jose.ExportedJWKSCache> {
    const publicJwk = await jose.exportJWK(DEFAULT.keyPair.publicKey)

    return {
      jwks: {
        keys: [publicJwk],
      },
      uat: Date.now() - 1000 * 60,
    }
  }

  describe("initialization", async () => {
    it("should throw an error if the openid scope is not included", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,

            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,

            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            authorizationParameters: {
              scope: "profile email",
            },

            fetch: getMockAuthorizationServer(),
          })
      ).toThrowError()
    })
  })

  describe("handler", async () => {
    it("should call the login handler if the path is /auth/login", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET",
      })
      authClient.handleLogin = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleLogin).toHaveBeenCalled()
    })

    it("should call the callback handler if the path is /auth/callback", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest("https://example.com/auth/callback", {
        method: "GET",
      })
      authClient.handleCallback = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleCallback).toHaveBeenCalled()
    })

    it("should call the logout handler if the path is /auth/logout", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest("https://example.com/auth/logout", {
        method: "GET",
      })
      authClient.handleLogout = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleLogout).toHaveBeenCalled()
    })

    it("should call the profile handler if the path is /auth/profile", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest("https://example.com/auth/profile", {
        method: "GET",
      })
      authClient.handleProfile = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleProfile).toHaveBeenCalled()
    })

    it("should call the access token handler if the path is /auth/access-token", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest("https://example.com/auth/access-token", {
        method: "GET",
      })
      authClient.handleAccessToken = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleAccessToken).toHaveBeenCalled()
    })

    it("should call the back-channel logout handler if the path is /auth/backchannel-logout", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest(
        "https://example.com/auth/backchannel-logout",
        {
          method: "POST",
        }
      )
      authClient.handleBackChannelLogout = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleBackChannelLogout).toHaveBeenCalled()
    })

    describe("rolling sessions - no matching auth route", async () => {
      it("should update the session expiry if a session exists", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,

          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })

        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456,
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000),
          },
        }
        const sessionCookie = await encrypt(session, secret)
        const headers = new Headers()
        headers.append("cookie", `__session=${sessionCookie}`)
        const request = new NextRequest(
          "https://example.com/dashboard/projects",
          {
            method: "GET",
            headers,
          }
        )

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
        const updatedTokenSet = {
          accessToken: "at_456",
          refreshToken: "rt_456",
          expiresAt,
        }
        authClient.getTokenSet = vi
          .fn()
          .mockResolvedValue([null, updatedTokenSet])

        const response = await authClient.handler(request)
        expect(authClient.getTokenSet).toHaveBeenCalled()

        // assert session has been updated
        const updatedSessionCookie = response.cookies.get("__session")
        expect(updatedSessionCookie).toBeDefined()
        const updatedSessionCookieValue = await decrypt(
          updatedSessionCookie!.value,
          secret
        )
        expect(updatedSessionCookieValue).toEqual({
          user: {
            sub: DEFAULT.sub,
          },
          tokenSet: {
            accessToken: "at_456",
            refreshToken: "rt_456",
            expiresAt: expect.any(Number),
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: expect.any(Number),
          },
        })

        // assert that the session expiry has been extended by the inactivity duration
        expect(updatedSessionCookie?.maxAge).toEqual(1800)
      })

      it("should pass the request through if there is no session", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,

          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })

        const request = new NextRequest(
          "https://example.com/dashboard/projects",
          {
            method: "GET",
          }
        )

        authClient.getTokenSet = vi.fn()

        const response = await authClient.handler(request)
        expect(authClient.getTokenSet).not.toHaveBeenCalled()

        // assert session has not been updated
        const updatedSessionCookie = response.cookies.get("__session")
        expect(updatedSessionCookie).toBeUndefined()
      })

      it("should pass the request through if there was an error fetching the updated token set", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,

          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })

        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456,
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000),
          },
        }
        const sessionCookie = await encrypt(session, secret)
        const headers = new Headers()
        headers.append("cookie", `__session=${sessionCookie}`)
        const request = new NextRequest(
          "https://example.com/dashboard/projects",
          {
            method: "GET",
            headers,
          }
        )

        authClient.getTokenSet = vi
          .fn()
          .mockResolvedValue([
            new Error("error fetching updated token set"),
            null,
          ])

        const response = await authClient.handler(request)
        expect(authClient.getTokenSet).toHaveBeenCalled()

        // assert session has not been updated
        const updatedSessionCookie = response.cookies.get("__session")
        expect(updatedSessionCookie).toBeUndefined()
      })
    })
  })

  describe("handleLogin", async () => {
    it("should redirect to the authorization server and store the transaction state", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const request = new NextRequest(
        new URL("/auth/login", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleLogin(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const authorizationUrl = new URL(response.headers.get("Location")!)
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      )
      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        `${DEFAULT.appBaseUrl}/auth/callback`
      )
      expect(authorizationUrl.searchParams.get("response_type")).toEqual("code")
      expect(authorizationUrl.searchParams.get("code_challenge")).not.toBeNull()
      expect(
        authorizationUrl.searchParams.get("code_challenge_method")
      ).toEqual("S256")
      expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
      expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
      expect(authorizationUrl.searchParams.get("scope")).toEqual(
        "openid profile email offline_access"
      )

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/",
      })
    })

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 }),
        }),
      })

      const request = new NextRequest(
        new URL("/auth/login", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleLogin(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "An error occured while trying to initiate the login request."
      )
    })

    describe("authorization parameters", async () => {
      it("should forward the query parameters to the authorization server", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
        loginUrl.searchParams.set("custom_param", "custom_value")
        loginUrl.searchParams.set("audience", "urn:mystore:api")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        )
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        )

        // transaction state
        const transactionCookie = response.cookies.get(
          `__txn_${authorizationUrl.searchParams.get("state")}`
        )
        expect(transactionCookie).toBeDefined()
        expect(await decrypt(transactionCookie!.value, secret)).toEqual({
          nonce: authorizationUrl.searchParams.get("nonce"),
          codeVerifier: expect.any(String),
          responseType: "code",
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/",
        })
      })

      it("should forward the configured authorization parameters to the authorization server", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            scope: "openid profile email offline_access custom_scope",
            audience: "urn:mystore:api",
            custom_param: "custom_value",
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        )
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        )
      })

      it("should override the configured authorization parameters with the query parameters", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            audience: "from-config",
            custom_param: "from-config",
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
        loginUrl.searchParams.set("custom_param", "from-query")
        loginUrl.searchParams.set("audience", "from-query")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        )
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-query"
        )
      })

      it("should not override internal authorization parameter values", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            client_id: "from-config",
            redirect_uri: "from-config",
            response_type: "from-config",
            code_challenge: "from-config",
            code_challenge_method: "from-config",
            state: "from-config",
            nonce: "from-config",
            // allowed to be overridden
            custom_param: "from-config",
            scope: "openid profile email offline_access custom_scope",
            audience: "from-config",
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
        loginUrl.searchParams.set("client_id", "from-query")
        loginUrl.searchParams.set("redirect_uri", "from-query")
        loginUrl.searchParams.set("response_type", "from-query")
        loginUrl.searchParams.set("code_challenge", "from-query")
        loginUrl.searchParams.set("code_challenge_method", "from-query")
        loginUrl.searchParams.set("state", "from-query")
        loginUrl.searchParams.set("nonce", "from-query")
        // allowed to be overridden
        loginUrl.searchParams.set("custom_param", "from-query")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        )
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        // allowed to be overridden
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-config"
        )
      })

      it("should not forward parameters with null or undefined values", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            scope: "openid profile email offline_access custom_scope",
            audience: null,
            custom_param: undefined,
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
        })
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        )
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toBeNull()
        expect(authorizationUrl.searchParams.get("audience")).toBeNull()
      })
    })

    it("should store the maxAge in the transaction state and forward it to the authorization server", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        authorizationParameters: {
          max_age: 3600,
        },

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
      const request = new NextRequest(loginUrl, {
        method: "GET",
      })

      const response = await authClient.handleLogin(request)
      const authorizationUrl = new URL(response.headers.get("Location")!)

      expect(authorizationUrl.searchParams.get("max_age")).toEqual("3600")

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        maxAge: 3600,
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/",
      })
    })

    it("should store the returnTo path in the transaction state", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })
      const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl)
      loginUrl.searchParams.set("returnTo", "/dashboard")
      const request = new NextRequest(loginUrl, {
        method: "GET",
      })

      const response = await authClient.handleLogin(request)
      const authorizationUrl = new URL(response.headers.get("Location")!)

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/dashboard",
      })
    })
  })

  describe("handleLogout", async () => {
    it("should redirect to the authorization server logout URL with the correct params", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456,
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const sessionCookie = await encrypt(session, secret)
      const headers = new Headers()
      headers.append("cookie", `__session=${sessionCookie}`)
      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers,
        }
      )

      const response = await authClient.handleLogout(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const authorizationUrl = new URL(response.headers.get("Location")!)
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      )
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}`)
      expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
        DEFAULT.sid
      )

      // session cookie is cleared
      const cookie = response.cookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
    })

    it("should use the returnTo URL as the post_logout_redirect_uri if provided", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456,
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const sessionCookie = await encrypt(session, secret)
      const headers = new Headers()
      headers.append("cookie", `__session=${sessionCookie}`)

      const url = new URL("/auth/logout", DEFAULT.appBaseUrl)
      url.searchParams.set("returnTo", `${DEFAULT.appBaseUrl}/some-other-page`)
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleLogout(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const authorizationUrl = new URL(response.headers.get("Location")!)
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      )
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}/some-other-page`)
      expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
        DEFAULT.sid
      )

      // session cookie is cleared
      const cookie = response.cookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
    })

    it("should not include the logout_hint parameter if a session does not exist", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleLogout(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const authorizationUrl = new URL(response.headers.get("Location")!)
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`)

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      )
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}`)
      expect(authorizationUrl.searchParams.get("logout_hint")).toBeNull()

      // session cookie is cleared
      const cookie = response.cookies.get("__session")
      expect(cookie?.value).toEqual("")
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"))
    })

    it("should fallback to the /v2/logout endpoint if the client does not have RP-Initiated Logout enabled", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          discoveryResponse: Response.json(
            {
              ..._authorizationServerMetadata,
              end_session_endpoint: null,
            },
            {
              status: 200,
              headers: {
                "content-type": "application/json",
              },
            }
          ),
        }),
      })

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleLogout(request)
      expect(response.status).toEqual(307)
      const logoutUrl = new URL(response.headers.get("Location")!)
      expect(logoutUrl.origin).toEqual(`https://${DEFAULT.domain}`)

      // query parameters
      expect(logoutUrl.searchParams.get("client_id")).toEqual(DEFAULT.clientId)
      expect(logoutUrl.searchParams.get("returnTo")).toEqual(DEFAULT.appBaseUrl)
    })

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 }),
        }),
      })

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleLogout(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "An error occured while trying to initiate the logout request."
      )
    })
  })

  describe("handleProfile", async () => {
    it("should return the user attributes stored in the session", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg",
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456,
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const sessionCookie = await encrypt(session, secret)
      const headers = new Headers()
      headers.append("cookie", `__session=${sessionCookie}`)
      const request = new NextRequest(
        new URL("/auth/profile", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers,
        }
      )

      const response = await authClient.handleProfile(request)
      expect(response.status).toEqual(200)
      expect(await response.json()).toEqual({
        sub: DEFAULT.sub,
        name: "John Doe",
        email: "john@example.com",
        picture: "https://example.com/john.jpg",
      })
    })

    it("should return a 401 if the user is not authenticated", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const request = new NextRequest(
        new URL("/auth/profile", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleProfile(request)
      expect(response.status).toEqual(401)
      expect(response.body).toBeNull()
    })
  })

  describe("handleCallback", async () => {
    it("should establish a session — happy path", async () => {
      const state = "transaction-state"
      const code = "auth-code"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("code", code)
      url.searchParams.set("state", state)

      const headers = new Headers()
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: "code",
        state: state,
        returnTo: "/dashboard",
      }
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret)}`
      )
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const redirectUrl = new URL(response.headers.get("Location")!)
      expect(redirectUrl.pathname).toEqual("/dashboard")

      // validate the session cookie
      const sessionCookie = response.cookies.get("__session")
      expect(sessionCookie).toBeDefined()
      const session = await decrypt(sessionCookie!.value, secret)
      expect(session).toEqual({
        user: {
          sub: DEFAULT.sub,
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: expect.any(Number),
        },
        internal: {
          sid: expect.any(String),
          createdAt: expect.any(Number),
        },
      })

      // validate the transaction cookie has been removed
      const transactionCookie = response.cookies.get(`__txn_${state}`)
      expect(transactionCookie).toBeDefined()
      expect(transactionCookie!.value).toEqual("")
      expect(transactionCookie!.expires).toEqual(
        new Date("1970-01-01T00:00:00.000Z")
      )
    })

    it("should return an error if the state parameter is missing", async () => {
      const code = "auth-code"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("code", code)

      const request = new NextRequest(url, {
        method: "GET",
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual("The state parameter is missing.")
    })

    it("should return an error if the transaction state could not be found", async () => {
      const state = "transaction-state"
      const code = "auth-code"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("code", code)
      url.searchParams.set("state", state)

      const headers = new Headers()
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: "code",
        state: state,
        returnTo: "/dashboard",
      }
      headers.set(
        "cookie",
        `__txn_does-not-exist=${await encrypt(transactionState, secret)}`
      )
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual("The state parameter is invalid.")
    })

    it("should return an error when there is an error authorizing the user", async () => {
      const state = "transaction-state"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("error", "some-error-code")
      url.searchParams.set("error_description", "some-error-description")
      url.searchParams.set("state", state)

      const headers = new Headers()
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: "code",
        state: state,
        returnTo: "/dashboard",
      }
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret)}`
      )
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "An error occured during the authorization flow."
      )
    })

    it("should return an error if there was an error during the code exchange", async () => {
      const state = "transaction-state"
      const code = "auth-code"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            error: "some-error-code",
            error_description: "some-error-description",
          },
        }),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("code", code)
      url.searchParams.set("state", state)

      const headers = new Headers()
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: "code",
        state: state,
        returnTo: "/dashboard",
      }
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret)}`
      )
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "An error occured while trying to exchange the authorization code."
      )
    })

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const state = "transaction-state"
      const code = "auth-code"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 }),
        }),
      })

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
      url.searchParams.set("code", code)
      url.searchParams.set("state", state)

      const headers = new Headers()
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: "code",
        state: state,
        returnTo: "/dashboard",
      }
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret)}`
      )
      const request = new NextRequest(url, {
        method: "GET",
        headers,
      })

      const response = await authClient.handleCallback(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "Discovery failed for the OpenID Connect configuration."
      )
    })

    describe("onCallback hook", async () => {
      it("should be called with the session data if the session is established", async () => {
        const state = "transaction-state"
        const code = "auth-code"

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/other-path", DEFAULT.appBaseUrl))
          )

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        // validate the new response redirect
        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/other-path")

        const expectedSession = {
          user: {
            sub: DEFAULT.sub,
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: expect.any(Number),
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number),
          },
        }
        const expectedContext = {
          returnTo: transactionState.returnTo,
        }

        expect(mockOnCallback).toHaveBeenCalledWith(
          null,
          expectedContext,
          expectedSession
        )

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeDefined()
        const session = await decrypt(sessionCookie!.value, secret)
        expect(session).toEqual(expectedSession)
      })

      it("should be called with an error if the state parameter is missing", async () => {
        const code = "auth-code"

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          )

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)

        const request = new NextRequest(url, {
          method: "GET",
        })

        // validate the new response redirect
        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/error-page")

        expect(mockOnCallback).toHaveBeenCalledWith(expect.any(Error), {}, null)
        expect(mockOnCallback.mock.calls[0][0].code).toEqual("missing_state")

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeUndefined()
      })

      it("should be called with an error if the transaction state could not be found", async () => {
        const state = "transaction-state"
        const code = "auth-code"

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          )

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_non-existent-state=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        // validate the new response redirect
        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/error-page")

        expect(mockOnCallback).toHaveBeenCalledWith(expect.any(Error), {}, null)
        expect(mockOnCallback.mock.calls[0][0].code).toEqual("invalid_state")

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeUndefined()
      })

      it("should be called with an error when there is an error authorizing the user", async () => {
        const state = "transaction-state"

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          )

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("error", "some-error-code")
        url.searchParams.set("error_description", "some-error-description")
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        // validate the new response redirect
        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/error-page")

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            returnTo: transactionState.returnTo,
          },
          null
        )
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          "authorization_error"
        )

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeUndefined()
      })

      it("should be called with an error if there was an error during the code exchange", async () => {
        const state = "transaction-state"
        const code = "auth-code"

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          )

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              error: "some-error-code",
              error_description: "some-error-description",
            },
          }),

          onCallback: mockOnCallback,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        // validate the new response redirect
        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/error-page")

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            returnTo: transactionState.returnTo,
          },
          null
        )
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          "authorization_code_grant_error"
        )

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeUndefined()
      })
    })

    describe("beforeSessionSaved hook", async () => {
      it("should use the return value of the hook as the session data", async () => {
        const state = "transaction-state"
        const code = "auth-code"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          beforeSessionSaved: async (session) => {
            return {
              ...session,
              user: {
                sub: DEFAULT.sub,
                name: "John Doe",
                email: "john@example.com",
                custom: "value",
              },
            }
          },
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/dashboard")

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeDefined()
        const session = await decrypt(sessionCookie!.value, secret)
        expect(session).toEqual({
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            custom: "value",
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: expect.any(Number),
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number),
          },
        })
      })

      it("should not call the hook if the session is not established", async () => {
        const mockBeforeSessionSaved = vi.fn()

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          beforeSessionSaved: mockBeforeSessionSaved,
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        const request = new NextRequest(url, {
          method: "GET",
        })

        await authClient.handleCallback(request)
        expect(mockBeforeSessionSaved).not.toHaveBeenCalled()
      })

      it("should not allow overwriting the internal session data", async () => {
        const state = "transaction-state"
        const code = "auth-code"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          // @ts-expect-error
          beforeSessionSaved: async (session) => {
            return {
              ...session,
              user: {
                sub: DEFAULT.sub,
                name: "John Doe",
                email: "john@example.com",
                custom: "value",
              },
              internal: null,
            }
          },
        })

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl)
        url.searchParams.set("code", code)
        url.searchParams.set("state", state)

        const headers = new Headers()
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: "code",
          state: state,
          returnTo: "/dashboard",
        }
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret)}`
        )
        const request = new NextRequest(url, {
          method: "GET",
          headers,
        })

        const response = await authClient.handleCallback(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const redirectUrl = new URL(response.headers.get("Location")!)
        expect(redirectUrl.pathname).toEqual("/dashboard")

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session")
        expect(sessionCookie).toBeDefined()
        const session = await decrypt(sessionCookie!.value, secret)
        expect(session).toEqual({
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            custom: "value",
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: expect.any(Number),
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number),
          },
        })
      })
    })
  })

  describe("handleAccessToken", async () => {
    it("should return the access token if the user has a session", async () => {
      const currentAccessToken = DEFAULT.accessToken
      const newAccessToken = "at_456"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: newAccessToken,
            expires_in: 86400, // expires in 10 days
          } as oauth.TokenEndpointResponse,
        }),
      })

      // we want to ensure the session is expired to return the refreshed access token
      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg",
        },
        tokenSet: {
          accessToken: currentAccessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt,
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const sessionCookie = await encrypt(session, secret)
      const headers = new Headers()
      headers.append("cookie", `__session=${sessionCookie}`)
      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers,
        }
      )

      const response = await authClient.handleAccessToken(request)
      expect(response.status).toEqual(200)
      expect(await response.json()).toEqual({
        token: newAccessToken,
        expires_at: expect.any(Number),
      })

      // validate that the session cookie has been updated
      const updatedSessionCookie = response.cookies.get("__session")
      const updatedSession = await decrypt<SessionData>(
        updatedSessionCookie!.value,
        secret
      )
      expect(updatedSession.tokenSet.accessToken).toEqual(newAccessToken)
    })

    it("should return a 401 if the user does not have a session", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
        }
      )

      const response = await authClient.handleAccessToken(request)
      expect(response.status).toEqual(401)
      expect(await response.json()).toEqual({
        error: {
          message: "The user does not have an active session.",
          code: "missing_session",
        },
      })

      // validate that the session cookie has not been set
      const sessionCookie = response.cookies.get("__session")
      expect(sessionCookie).toBeUndefined()
    })

    it("should return an error if obtaining a token set failed", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg",
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          // missing refresh token
          expiresAt,
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }
      const sessionCookie = await encrypt(session, secret)
      const headers = new Headers()
      headers.append("cookie", `__session=${sessionCookie}`)
      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers,
        }
      )

      const response = await authClient.handleAccessToken(request)
      expect(response.status).toEqual(401)
      expect(await response.json()).toEqual({
        error: {
          message:
            "The access token has expired and a refresh token was not provided. The user needs to re-authenticate.",
          code: "missing_refresh_token",
        },
      })

      // validate that the session cookie has not been set
      expect(response.cookies.get("__session")).toBeUndefined()
    })
  })

  describe("handleBackChannelLogout", async () => {
    it("should return a 204 when successful — happy path", async () => {
      const deleteByLogoutTokenSpy = vi.fn()
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn(),
          deleteByLogoutToken: deleteByLogoutTokenSpy,
        },
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS(),
      })

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({}),
          }),
        }
      )

      const response = await authClient.handleBackChannelLogout(request)
      expect(response.status).toEqual(204)
      expect(response.body).toBeNull()

      expect(deleteByLogoutTokenSpy).toHaveBeenCalledWith({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid,
      })
    })

    it("should return a 500 if a session store is not configured", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      // pass in a stateless session store that does not implement a store
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS(),
      })

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({}),
          }),
        }
      )

      const response = await authClient.handleBackChannelLogout(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "A session data store is not configured."
      )
    })

    it("should return a 500 if a session store deleteByLogoutToken method is not implemented", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn(),
        },
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS(),
      })

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({}),
          }),
        }
      )

      const response = await authClient.handleBackChannelLogout(request)
      expect(response.status).toEqual(500)
      expect(await response.text()).toEqual(
        "Back-channel logout is not supported by the session data store."
      )
    })

    describe("malformed logout tokens", async () => {
      it("should return a 400 if a logout token contains a nonce", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  nonce: "nonce-value", // nonce should NOT be present
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if a logout token is not provided in the request", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({}),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if a logout token does not contain a sid nor sub", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sid: null,
                  sub: null,
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if the sub claim is not a string", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sub: 123,
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if the sid claim is not a string", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sid: 123,
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if the events claim is missing", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: null,
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if the events object does not contain the backchannel logout member", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: {},
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })

      it("should return a 400 if the backchannel event is not an object", async () => {
        const deleteByLogoutTokenSpy = vi.fn()
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy,
          },
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS(),
        })

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: {
                    "http://schemas.openid.net/event/backchannel-logout":
                      "some string",
                  },
                },
              }),
            }),
          }
        )

        const response = await authClient.handleBackChannelLogout(request)
        expect(response.status).toEqual(400)
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled()
      })
    })
  })

  describe("getTokenSet", async () => {
    it("should return the access token if it has not expired", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60 // expires in 10 days
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt,
      }

      const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
      expect(error).toBeNull()
      expect(updatedTokenSet).toEqual(tokenSet)
    })

    it("should return an error if the token set does not contain a refresh token and the access token has expired", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer(),
      })

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        expiresAt,
      }

      const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
      expect(error?.code).toEqual("missing_refresh_token")
      expect(updatedTokenSet).toBeNull()
    })

    it("should refresh the access token if it expired", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: DEFAULT.accessToken,
            expires_in: 86400, // expires in 10 days
          } as oauth.TokenEndpointResponse,
        }),
      })

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt,
      }

      const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
      expect(error).toBeNull()
      expect(updatedTokenSet).toEqual({
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt: expect.any(Number),
      })
    })

    it("should return an error if an error occurred during the refresh token exchange", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            error: "some-error-code",
            error_description: "some-error-description",
          },
        }),
      })

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt,
      }

      const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
      expect(error?.code).toEqual("failed_to_refresh_token")
      expect(updatedTokenSet).toBeNull()
    })

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 }),
        }),
      })

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt,
      }

      const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
      expect(error?.code).toEqual("discovery_error")
      expect(updatedTokenSet).toBeNull()
    })

    describe("rotating refresh token", async () => {
      it("should refresh the access token if it expired along with the updated refresh token", async () => {
        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: DEFAULT.accessToken,
              refresh_token: "rt_456",
              expires_in: 86400, // expires in 10 days
            } as oauth.TokenEndpointResponse,
          }),
        })

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60 // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt,
        }

        const [error, updatedTokenSet] = await authClient.getTokenSet(tokenSet)
        expect(error).toBeNull()
        expect(updatedTokenSet).toEqual({
          accessToken: DEFAULT.accessToken,
          refreshToken: "rt_456",
          expiresAt: expect.any(Number),
        })
      })
    })
  })
})

const _authorizationServerMetadata = {
  issuer: "https://guabu.us.auth0.com/",
  authorization_endpoint: "https://guabu.us.auth0.com/authorize",
  token_endpoint: "https://guabu.us.auth0.com/oauth/token",
  device_authorization_endpoint: "https://guabu.us.auth0.com/oauth/device/code",
  userinfo_endpoint: "https://guabu.us.auth0.com/userinfo",
  mfa_challenge_endpoint: "https://guabu.us.auth0.com/mfa/challenge",
  jwks_uri: "https://guabu.us.auth0.com/.well-known/jwks.json",
  registration_endpoint: "https://guabu.us.auth0.com/oidc/register",
  revocation_endpoint: "https://guabu.us.auth0.com/oauth/revoke",
  scopes_supported: [
    "openid",
    "profile",
    "offline_access",
    "name",
    "given_name",
    "family_name",
    "nickname",
    "email",
    "email_verified",
    "picture",
    "created_at",
    "identities",
    "phone",
    "address",
  ],
  response_types_supported: [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token",
  ],
  code_challenge_methods_supported: ["S256", "plain"],
  response_modes_supported: ["query", "fragment", "form_post"],
  subject_types_supported: ["public"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
  ],
  claims_supported: [
    "aud",
    "auth_time",
    "created_at",
    "email",
    "email_verified",
    "exp",
    "family_name",
    "given_name",
    "iat",
    "identities",
    "iss",
    "name",
    "nickname",
    "phone_number",
    "picture",
    "sub",
  ],
  request_uri_parameter_supported: false,
  request_parameter_supported: false,
  id_token_signing_alg_values_supported: ["HS256", "RS256", "PS256"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256", "RS384", "PS256"],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  end_session_endpoint: "https://guabu.us.auth0.com/oidc/logout",
}
