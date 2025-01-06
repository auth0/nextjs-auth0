import { NextResponse, type NextRequest } from "next/server"
import * as jose from "jose"
import * as oauth from "oauth4webapi"

import {
  AccessTokenError,
  AccessTokenErrorCode,
  AuthorizationCodeGrantError,
  AuthorizationError,
  BackchannelLogoutError,
  DiscoveryError,
  InvalidStateError,
  MissingStateError,
  OAuth2Error,
  SdkError,
} from "../errors"
import { LogoutToken, SessionData, TokenSet } from "../types"
import { AbstractSessionStore } from "./session/abstract-session-store"
import { TransactionState, TransactionStore } from "./transaction-store"
import { filterClaims } from "./user"

export type BeforeSessionSavedHook = (
  session: SessionData,
  idToken: string | null
) => Promise<SessionData>

type OnCallbackContext = {
  returnTo?: string
}
export type OnCallbackHook = (
  error: SdkError | null,
  ctx: OnCallbackContext,
  session: SessionData | null
) => Promise<NextResponse>

// params passed to the /authorize endpoint that cannot be overwritten
const INTERNAL_AUTHORIZE_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce",
]

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"].join(
  " "
)

export interface AuthorizationParameters {
  /**
   * The list of scopes to request authorization for.
   *
   * Defaults to `"openid profile email offline_access"`.
   */
  scope?: string
  /**
   * The maximum amount of time, in seconds, after which a user must reauthenticate.
   */
  max_age?: number
  /**
   * Additional authorization parameters.
   */
  [key: string]: unknown
}

interface Routes {
  login: string
  logout: string
  callback: string
  profile: string
  accessToken: string
  backChannelLogout: string
}
export type RoutesOptions = Partial<
  Pick<Routes, "login" | "callback" | "logout" | "backChannelLogout">
>

export interface AuthClientOptions {
  transactionStore: TransactionStore
  sessionStore: AbstractSessionStore

  domain: string
  clientId: string
  clientSecret?: string
  clientAssertionSigningKey?: string | CryptoKey
  clientAssertionSigningAlg?: string
  authorizationParameters?: AuthorizationParameters
  pushedAuthorizationRequests?: boolean

  secret: string
  appBaseUrl: string
  signInReturnToPath?: string

  beforeSessionSaved?: BeforeSessionSavedHook
  onCallback?: OnCallbackHook

  routes?: RoutesOptions

  // custom fetch implementation to allow for dependency injection
  fetch?: typeof fetch
  jwksCache?: jose.JWKSCacheInput
  allowInsecureRequests?: boolean
}

export class AuthClient {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore

  private clientMetadata: oauth.Client
  private clientSecret?: string
  private clientAssertionSigningKey?: string | CryptoKey
  private clientAssertionSigningAlg: string
  private domain: string
  private authorizationParameters: AuthorizationParameters
  private pushedAuthorizationRequests: boolean

  private appBaseUrl: string
  private signInReturnToPath: string

  private beforeSessionSaved?: BeforeSessionSavedHook
  private onCallback: OnCallbackHook

  private routes: Routes

  private fetch: typeof fetch
  private jwksCache: jose.JWKSCacheInput
  private allowInsecureRequests: boolean

  constructor(options: AuthClientOptions) {
    // dependencies
    this.fetch = options.fetch || fetch
    this.jwksCache = options.jwksCache || {}
    this.allowInsecureRequests = options.allowInsecureRequests ?? false

    if (this.allowInsecureRequests && process.env.NODE_ENV === "production") {
      console.warn(
        "allowInsecureRequests is enabled in a production environment. This is not recommended."
      )
    }

    // stores
    this.transactionStore = options.transactionStore
    this.sessionStore = options.sessionStore

    // authorization server
    this.domain = options.domain
    this.clientMetadata = { client_id: options.clientId }
    this.clientSecret = options.clientSecret
    this.authorizationParameters = options.authorizationParameters || {
      scope: DEFAULT_SCOPES,
    }
    this.pushedAuthorizationRequests =
      options.pushedAuthorizationRequests ?? false
    this.clientAssertionSigningKey = options.clientAssertionSigningKey
    this.clientAssertionSigningAlg =
      options.clientAssertionSigningAlg || "RS256"

    if (!this.authorizationParameters.scope) {
      this.authorizationParameters.scope = DEFAULT_SCOPES
    }

    const scope = this.authorizationParameters.scope
      .split(" ")
      .map((s) => s.trim())
    if (!scope.includes("openid")) {
      throw new Error(
        "The 'openid' scope must be included in the set of scopes. See https://auth0.com/docs"
      )
    }

    // application
    this.appBaseUrl = options.appBaseUrl
    this.signInReturnToPath = options.signInReturnToPath || "/"

    // hooks
    this.beforeSessionSaved = options.beforeSessionSaved
    this.onCallback = options.onCallback || this.defaultOnCallback

    // routes
    this.routes = {
      login: "/auth/login",
      logout: "/auth/logout",
      callback: "/auth/callback",
      backChannelLogout: "/auth/backchannel-logout",
      profile: process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
      accessToken:
        process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
      ...options.routes,
    }
  }

  async handler(req: NextRequest): Promise<NextResponse> {
    const { pathname } = req.nextUrl
    const method = req.method

    if (method === "GET" && pathname === this.routes.login) {
      return this.handleLogin(req)
    } else if (method === "GET" && pathname === this.routes.logout) {
      return this.handleLogout(req)
    } else if (method === "GET" && pathname === this.routes.callback) {
      return this.handleCallback(req)
    } else if (method === "GET" && pathname === this.routes.profile) {
      return this.handleProfile(req)
    } else if (method === "GET" && pathname === this.routes.accessToken) {
      return this.handleAccessToken(req)
    } else if (
      method === "POST" &&
      pathname === this.routes.backChannelLogout
    ) {
      return this.handleBackChannelLogout(req)
    } else {
      // no auth handler found, simply touch the sessions
      // TODO: this should only happen if rolling sessions are enabled. Also, we should
      // try to avoid reading from the DB (for stateful sessions) on every request if possible.
      const res = NextResponse.next()
      const session = await this.sessionStore.get(req.cookies)

      if (session) {
        // we pass the existing session (containing an `createdAt` timestamp) to the set method
        // which will update the cookie's `maxAge` property based on the `createdAt` time
        await this.sessionStore.set(req.cookies, res.cookies, {
          ...session,
        })
      }

      return res
    }
  }

  async handleLogin(req: NextRequest): Promise<NextResponse> {
    const redirectUri = new URL(this.routes.callback, this.appBaseUrl) // must be registed with the authorization server
    const returnTo =
      req.nextUrl.searchParams.get("returnTo") || this.signInReturnToPath

    const codeChallengeMethod = "S256"
    const codeVerifier = oauth.generateRandomCodeVerifier()
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)
    const state = oauth.generateRandomState()
    const nonce = oauth.generateRandomNonce()

    const authorizationParams = new URLSearchParams()
    authorizationParams.set("client_id", this.clientMetadata.client_id)
    authorizationParams.set("redirect_uri", redirectUri.toString())
    authorizationParams.set("response_type", "code")
    authorizationParams.set("code_challenge", codeChallenge)
    authorizationParams.set("code_challenge_method", codeChallengeMethod)
    authorizationParams.set("state", state)
    authorizationParams.set("nonce", nonce)

    // any custom params to forward to /authorize defined as configuration
    Object.entries(this.authorizationParameters).forEach(([key, val]) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key)) {
        if (val === null || val === undefined) {
          return
        }

        authorizationParams.set(key, String(val))
      }
    })

    // any custom params to forward to /authorize passed as query parameters
    req.nextUrl.searchParams.forEach((val, key) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key)) {
        authorizationParams.set(key, val)
      }
    })

    const transactionState: TransactionState = {
      nonce,
      maxAge: this.authorizationParameters.max_age,
      codeVerifier: codeVerifier,
      responseType: "code",
      state,
      returnTo,
    }

    const [error, authorizationUrl] =
      await this.authorizationUrl(authorizationParams)
    if (error) {
      return new NextResponse(
        "An error occured while trying to initiate the login request.",
        {
          status: 500,
        }
      )
    }

    const res = NextResponse.redirect(authorizationUrl.toString())
    await this.transactionStore.save(res.cookies, transactionState)

    return res
  }

  async handleLogout(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies)
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata()

    if (discoveryError) {
      return new NextResponse(
        "An error occured while trying to initiate the logout request.",
        {
          status: 500,
        }
      )
    }

    const returnTo = req.nextUrl.searchParams.get("returnTo") || this.appBaseUrl

    if (!authorizationServerMetadata.end_session_endpoint) {
      // the Auth0 client does not have RP-initiated logout enabled, redirect to the `/v2/logout` endpoint
      console.warn(
        "The Auth0 client does not have RP-initiated logout enabled, the user will be redirected to the `/v2/logout` endpoint instead. Learn how to enable it here: https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#enable-endpoint-discovery"
      )
      const url = new URL("/v2/logout", this.issuer)
      url.searchParams.set("returnTo", returnTo)
      url.searchParams.set("client_id", this.clientMetadata.client_id)

      const res = NextResponse.redirect(url)
      await this.sessionStore.delete(req.cookies, res.cookies)
      return res
    }

    const url = new URL(authorizationServerMetadata.end_session_endpoint)
    url.searchParams.set("client_id", this.clientMetadata.client_id)
    url.searchParams.set("post_logout_redirect_uri", returnTo)

    if (session?.internal.sid) {
      url.searchParams.set("logout_hint", session.internal.sid)
    }

    const res = NextResponse.redirect(url)
    await this.sessionStore.delete(req.cookies, res.cookies)

    return res
  }

  async handleCallback(req: NextRequest): Promise<NextResponse> {
    const state = req.nextUrl.searchParams.get("state")
    if (!state) {
      return this.onCallback(new MissingStateError(), {}, null)
    }

    const transactionState = await this.transactionStore.get(req.cookies, state)
    if (!transactionState) {
      return this.onCallback(new InvalidStateError(), {}, null)
    }

    const onCallbackCtx: OnCallbackContext = {
      returnTo: transactionState.returnTo,
    }

    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata()

    if (discoveryError) {
      return this.onCallback(discoveryError, onCallbackCtx, null)
    }

    let codeGrantParams: URLSearchParams
    try {
      codeGrantParams = oauth.validateAuthResponse(
        authorizationServerMetadata,
        this.clientMetadata,
        req.nextUrl.searchParams,
        transactionState.state
      )
    } catch (e: any) {
      return this.onCallback(
        new AuthorizationError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description,
          }),
        }),
        onCallbackCtx,
        null
      )
    }

    const redirectUri = new URL(this.routes.callback, this.appBaseUrl) // must be registed with the authorization server
    const codeGrantResponse = await oauth.authorizationCodeGrantRequest(
      authorizationServerMetadata,
      this.clientMetadata,
      await this.getClientAuth(),
      codeGrantParams,
      redirectUri.toString(),
      transactionState.codeVerifier,
      {
        [oauth.customFetch]: this.fetch,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests,
      }
    )

    let oidcRes: oauth.TokenEndpointResponse
    try {
      oidcRes = await oauth.processAuthorizationCodeResponse(
        authorizationServerMetadata,
        this.clientMetadata,
        codeGrantResponse,
        {
          expectedNonce: transactionState.nonce,
          maxAge: transactionState.maxAge,
          requireIdToken: true,
        }
      )
    } catch (e: any) {
      return this.onCallback(
        new AuthorizationCodeGrantError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description,
          }),
        }),
        onCallbackCtx,
        null
      )
    }

    const idTokenClaims = oauth.getValidatedIdTokenClaims(oidcRes)!
    let session: SessionData = {
      user: idTokenClaims,
      tokenSet: {
        accessToken: oidcRes.access_token,
        refreshToken: oidcRes.refresh_token,
        expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in),
      },
      internal: {
        sid: idTokenClaims.sid as string,
        createdAt: Math.floor(Date.now() / 1000),
      },
    }

    const res = await this.onCallback(null, onCallbackCtx, session)

    if (this.beforeSessionSaved) {
      const updatedSession = await this.beforeSessionSaved(
        session,
        oidcRes.id_token ?? null
      )
      session = {
        ...updatedSession,
        internal: session.internal,
      }
    } else {
      session.user = filterClaims(idTokenClaims)
    }

    await this.sessionStore.set(req.cookies, res.cookies, session, true)
    await this.transactionStore.delete(res.cookies, state)

    return res
  }

  async handleProfile(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies)

    if (!session) {
      return new NextResponse(null, {
        status: 401,
      })
    }

    return NextResponse.json(session?.user)
  }

  async handleAccessToken(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies)

    if (!session) {
      return NextResponse.json(
        {
          error: {
            message: "The user does not have an active session.",
            code: AccessTokenErrorCode.MISSING_SESSION,
          },
        },
        {
          status: 401,
        }
      )
    }

    const [error, updatedTokenSet] = await this.getTokenSet(session.tokenSet)

    if (error) {
      return NextResponse.json(
        {
          error: {
            message: error.message,
            code: error.code,
          },
        },
        {
          status: 401,
        }
      )
    }

    const res = NextResponse.json({
      token: updatedTokenSet.accessToken,
      expires_at: updatedTokenSet.expiresAt,
    })

    await this.sessionStore.set(req.cookies, res.cookies, {
      ...session,
      tokenSet: updatedTokenSet,
    })

    return res
  }

  async handleBackChannelLogout(req: NextRequest): Promise<NextResponse> {
    if (!this.sessionStore.store) {
      return new NextResponse("A session data store is not configured.", {
        status: 500,
      })
    }

    if (!this.sessionStore.store.deleteByLogoutToken) {
      return new NextResponse(
        "Back-channel logout is not supported by the session data store.",
        {
          status: 500,
        }
      )
    }

    const body = new URLSearchParams(await req.text())
    const logoutToken = body.get("logout_token")

    if (!logoutToken) {
      return new NextResponse("Missing `logout_token` in the request body.", {
        status: 400,
      })
    }

    const [error, logoutTokenClaims] = await this.verifyLogoutToken(logoutToken)
    if (error) {
      return new NextResponse(error.message, {
        status: 400,
      })
    }

    await this.sessionStore.store.deleteByLogoutToken(logoutTokenClaims)

    return new NextResponse(null, {
      status: 204,
    })
  }

  /**
   * getTokenSet returns a valid token set. If the access token has expired, it will attempt to
   * refresh it using the refresh token, if available.
   */
  async getTokenSet(
    tokenSet: TokenSet
  ): Promise<[null, TokenSet] | [SdkError, null]> {
    // the access token has expired but we do not have a refresh token
    if (!tokenSet.refreshToken && tokenSet.expiresAt <= Date.now() / 1000) {
      return [
        new AccessTokenError(
          AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
          "The access token has expired and a refresh token was not provided. The user needs to re-authenticate."
        ),
        null,
      ]
    }

    // the access token has expired and we have a refresh token
    if (tokenSet.refreshToken && tokenSet.expiresAt <= Date.now() / 1000) {
      const [discoveryError, authorizationServerMetadata] =
        await this.discoverAuthorizationServerMetadata()

      if (discoveryError) {
        console.error(discoveryError)
        return [discoveryError, null]
      }

      const refreshTokenRes = await oauth.refreshTokenGrantRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        await this.getClientAuth(),
        tokenSet.refreshToken,
        {
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests,
        }
      )

      let oauthRes: oauth.TokenEndpointResponse
      try {
        oauthRes = await oauth.processRefreshTokenResponse(
          authorizationServerMetadata,
          this.clientMetadata,
          refreshTokenRes
        )
      } catch (e: any) {
        console.error(e)
        return [
          new AccessTokenError(
            AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN,
            "The access token has expired and there was an error while trying to refresh it. Check the server logs for more information."
          ),
          null,
        ]
      }

      const accessTokenExpiresAt =
        Math.floor(Date.now() / 1000) + Number(oauthRes.expires_in)

      let updatedTokenSet = {
        ...tokenSet, // contains the existing `iat` claim to maintain the session lifetime
        accessToken: oauthRes.access_token,
        expiresAt: accessTokenExpiresAt,
      }

      if (oauthRes.refresh_token) {
        // refresh token rotation is enabled, persist the new refresh token from the response
        updatedTokenSet.refreshToken = oauthRes.refresh_token
      } else {
        // we did not get a refresh token back, keep the current long-lived refresh token around
        updatedTokenSet.refreshToken = tokenSet.refreshToken
      }

      return [null, updatedTokenSet]
    }

    return [null, tokenSet]
  }

  private async discoverAuthorizationServerMetadata(): Promise<
    [null, oauth.AuthorizationServer] | [SdkError, null]
  > {
    const issuer = new URL(this.issuer)

    try {
      const authorizationServerMetadata = await oauth
        .discoveryRequest(issuer, {
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests,
        })
        .then((response) => oauth.processDiscoveryResponse(issuer, response))

      return [null, authorizationServerMetadata]
    } catch (e) {
      console.error(
        `An error occured while performing the discovery request. Please make sure the AUTH0_DOMAIN environment variable is correctly configured — the format must be 'example.us.auth0.com'. issuer=${issuer.toString()}, error:`,
        e
      )
      return [
        new DiscoveryError(
          "Discovery failed for the OpenID Connect configuration."
        ),
        null,
      ]
    }
  }

  private async defaultOnCallback(
    error: SdkError | null,
    ctx: OnCallbackContext,
    _session: SessionData | null
  ) {
    if (error) {
      return new NextResponse(error.message, {
        status: 500,
      })
    }

    const res = NextResponse.redirect(
      new URL(ctx.returnTo || "/", this.appBaseUrl)
    )

    return res
  }

  private async verifyLogoutToken(
    logoutToken: string
  ): Promise<[null, LogoutToken] | [SdkError, null]> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata()

    if (discoveryError) {
      return [discoveryError, null]
    }

    // only `RS256` is supported for logout tokens
    const ID_TOKEN_SIGNING_ALG = "RS256"

    const keyInput = jose.createRemoteJWKSet(
      new URL(authorizationServerMetadata.jwks_uri!),
      {
        [jose.jwksCache]: this.jwksCache,
      }
    )

    const { payload } = await jose.jwtVerify(logoutToken, keyInput, {
      issuer: authorizationServerMetadata.issuer,
      audience: this.clientMetadata.client_id,
      algorithms: [ID_TOKEN_SIGNING_ALG],
      requiredClaims: ["iat"],
    })

    if (!("sid" in payload) && !("sub" in payload)) {
      return [
        new BackchannelLogoutError(
          'either "sid" or "sub" (or both) claims must be present'
        ),
        null,
      ]
    }

    if ("sid" in payload && typeof payload.sid !== "string") {
      return [new BackchannelLogoutError('"sid" claim must be a string'), null]
    }

    if ("sub" in payload && typeof payload.sub !== "string") {
      return [new BackchannelLogoutError('"sub" claim must be a string'), null]
    }

    if ("nonce" in payload) {
      return [new BackchannelLogoutError('"nonce" claim is prohibited'), null]
    }

    if (!("events" in payload)) {
      return [new BackchannelLogoutError('"events" claim is missing'), null]
    }

    if (typeof payload.events !== "object" || payload.events === null) {
      return [
        new BackchannelLogoutError('"events" claim must be an object'),
        null,
      ]
    }

    if (
      !("http://schemas.openid.net/event/backchannel-logout" in payload.events)
    ) {
      return [
        new BackchannelLogoutError(
          '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
        ),
        null,
      ]
    }

    if (
      typeof payload.events[
        "http://schemas.openid.net/event/backchannel-logout"
      ] !== "object"
    ) {
      return [
        new BackchannelLogoutError(
          '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object'
        ),
        null,
      ]
    }

    return [
      null,
      {
        sid: payload.sid as string,
        sub: payload.sub,
      },
    ]
  }

  private async authorizationUrl(
    params: URLSearchParams
  ): Promise<[null, URL] | [Error, null]> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata()
    if (discoveryError) {
      return [discoveryError, null]
    }

    if (
      this.pushedAuthorizationRequests &&
      !authorizationServerMetadata.pushed_authorization_request_endpoint
    ) {
      console.error(
        "The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par"
      )
      return [
        new Error(
          "The authorization server does not support pushed authorization requests."
        ),
        null,
      ]
    }

    const authorizationUrl = new URL(
      authorizationServerMetadata.authorization_endpoint!
    )

    if (this.pushedAuthorizationRequests) {
      // push the request params to the authorization server
      const response = await oauth.pushedAuthorizationRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        await this.getClientAuth(),
        params,
        {
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests,
        }
      )

      let parRes: oauth.PushedAuthorizationResponse
      try {
        parRes = await oauth.processPushedAuthorizationResponse(
          authorizationServerMetadata,
          this.clientMetadata,
          response
        )
      } catch (e: any) {
        return [
          new AuthorizationError({
            cause: new OAuth2Error({
              code: e.error,
              message: e.error_description,
            }),
            message:
              "An error occured while pushing the authorization request.",
          }),
          null,
        ]
      }

      authorizationUrl.searchParams.set("request_uri", parRes.request_uri)
      authorizationUrl.searchParams.set(
        "client_id",
        this.clientMetadata.client_id
      )

      return [null, authorizationUrl]
    }

    // append the query parameters to the authorization URL for the normal flow
    authorizationUrl.search = params.toString()

    return [null, authorizationUrl]
  }

  private async getClientAuth(): Promise<oauth.ClientAuth> {
    if (!this.clientSecret && !this.clientAssertionSigningKey) {
      throw new Error(
        "The client secret or client assertion signing key must be provided."
      )
    }

    let clientPrivateKey = this.clientAssertionSigningKey as
      | CryptoKey
      | undefined

    if (clientPrivateKey && !(clientPrivateKey instanceof CryptoKey)) {
      clientPrivateKey = await jose.importPKCS8<CryptoKey>(
        clientPrivateKey,
        this.clientAssertionSigningAlg
      )
    }

    return clientPrivateKey
      ? oauth.PrivateKeyJwt(clientPrivateKey)
      : oauth.ClientSecretPost(this.clientSecret!)
  }

  private get issuer(): string {
    return this.domain.startsWith("http://") ||
      this.domain.startsWith("https://")
      ? this.domain
      : `https://${this.domain}`
  }
}
