import { NextResponse, type NextRequest } from "next/server"
import * as jose from "jose"
import * as oauth from "oauth4webapi"

import {
  AuthorizationCodeGrantError,
  AuthorizationError,
  BackchannelLogoutError,
  DiscoveryError,
  InvalidStateError,
  MissingRefreshToken,
  MissingStateError,
  OAuth2Error,
  RefreshTokenGrantError,
  SdkError,
} from "../errors"
import {
  AbstractSessionStore,
  LogoutToken,
  SessionData,
  TokenSet,
} from "./session/abstract-session-store"
import { TransactionState, TransactionStore } from "./transaction-store"
import { filterClaims } from "./user"

export type BeforeSessionSavedHook = (
  session: SessionData
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

export interface AuthClientOptions {
  transactionStore: TransactionStore
  sessionStore: AbstractSessionStore

  domain: string
  clientId: string
  clientSecret: string
  authorizationParameters?: AuthorizationParameters

  secret: string
  appBaseUrl: string
  signInReturnToPath?: string

  beforeSessionSaved?: BeforeSessionSavedHook
  onCallback?: OnCallbackHook

  // custom fetch implementation to allow for dependency injection
  fetch?: typeof fetch
  jwksCache?: jose.JWKSCacheInput
}

export class AuthClient {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore

  private clientMetadata: oauth.Client
  private clientSecret: string
  private issuer: string
  private authorizationParameters: AuthorizationParameters

  private appBaseUrl: string
  private signInReturnToPath: string

  private beforeSessionSaved?: BeforeSessionSavedHook
  private onCallback: OnCallbackHook

  private fetch: typeof fetch
  private jwksCache: jose.JWKSCacheInput

  constructor(options: AuthClientOptions) {
    // dependencies
    this.fetch = options.fetch || fetch
    this.jwksCache = options.jwksCache || {}

    // stores
    this.transactionStore = options.transactionStore
    this.sessionStore = options.sessionStore

    // authorization server
    this.issuer = `https://${options.domain}`
    this.clientMetadata = { client_id: options.clientId }
    this.clientSecret = options.clientSecret
    this.authorizationParameters = options.authorizationParameters || {
      scope: DEFAULT_SCOPES,
    }

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
  }

  async handler(req: NextRequest): Promise<NextResponse> {
    const { pathname } = req.nextUrl
    const method = req.method

    if (method === "GET" && pathname === "/auth/login") {
      return this.handleLogin(req)
    } else if (method === "GET" && pathname === "/auth/logout") {
      return this.handleLogout(req)
    } else if (method === "GET" && pathname === "/auth/callback") {
      return this.handleCallback(req)
    } else if (method === "GET" && pathname === "/auth/profile") {
      return this.handleProfile(req)
    } else if (method === "GET" && pathname === "/auth/access-token") {
      return this.handleAccessToken(req)
    } else if (method === "POST" && pathname === "/auth/backchannel-logout") {
      return this.handleBackChannelLogout(req)
    } else {
      // no auth handler found, simply touch the sessions
      // TODO: this should only happen if rolling sessions are enabled. Also, we should
      // try to avoid reading from the DB (for stateful sessions) on every request if possible.
      const res = NextResponse.next()
      const session = await this.sessionStore.get(req.cookies)

      if (session) {
        // refresh the access token, if necessary
        const [error, updatedTokenSet] = await this.getTokenSet(
          session.tokenSet
        )

        if (error) {
          // TODO: accept a logger in the constructor to log these errors
          console.error(`Failed to fetch token set: ${error.message}`)
          return res
        }

        // we pass the existing session (containing an `createdAt` timestamp) to the set method
        // which will update the cookie's `maxAge` property based on the `createdAt` time
        await this.sessionStore.set(req.cookies, res.cookies, {
          ...session,
          tokenSet: updatedTokenSet,
        })
      }

      return res
    }
  }

  async handleLogin(req: NextRequest): Promise<NextResponse> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata()

    if (discoveryError) {
      return new NextResponse(
        "An error occured while trying to initiate the login request.",
        {
          status: 500,
        }
      )
    }

    const redirectUri = new URL("/auth/callback", this.appBaseUrl) // must be registed with the authorization server
    const returnTo =
      req.nextUrl.searchParams.get("returnTo") || this.signInReturnToPath

    const codeChallengeMethod = "S256"
    const codeVerifier = oauth.generateRandomCodeVerifier()
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)
    const state = oauth.generateRandomState()
    const nonce = oauth.generateRandomNonce()

    const authorizationUrl = new URL(
      authorizationServerMetadata.authorization_endpoint!
    )
    authorizationUrl.searchParams.set(
      "client_id",
      this.clientMetadata.client_id
    )
    authorizationUrl.searchParams.set("redirect_uri", redirectUri.toString())
    authorizationUrl.searchParams.set("response_type", "code")
    authorizationUrl.searchParams.set("code_challenge", codeChallenge)
    authorizationUrl.searchParams.set(
      "code_challenge_method",
      codeChallengeMethod
    )
    authorizationUrl.searchParams.set("state", state)
    authorizationUrl.searchParams.set("nonce", nonce)

    // any custom params to forward to /authorize defined as configuration
    Object.entries(this.authorizationParameters).forEach(([key, val]) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key)) {
        if (val === null || val === undefined) {
          return
        }

        authorizationUrl.searchParams.set(key, String(val))
      }
    })

    // any custom params to forward to /authorize passed as query parameters
    req.nextUrl.searchParams.forEach((val, key) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key)) {
        authorizationUrl.searchParams.set(key, val)
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

    if (!authorizationServerMetadata.end_session_endpoint) {
      console.error(
        "The Auth0 client does not have RP-initiated logout enabled. Learn how to enable it here: https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#enable-endpoint-discovery"
      )
      return new NextResponse(
        "An error occured while trying to initiate the logout request.",
        {
          status: 500,
        }
      )
    }

    const url = new URL(authorizationServerMetadata.end_session_endpoint)
    url.searchParams.set("client_id", this.clientMetadata.client_id)
    url.searchParams.set(
      "post_logout_redirect_uri",
      req.nextUrl.searchParams.get("returnTo") || this.appBaseUrl
    )

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

    const redirectUri = new URL("/auth/callback", this.appBaseUrl) // must be registed with the authorization server
    const codeGrantResponse = await oauth.authorizationCodeGrantRequest(
      authorizationServerMetadata,
      this.clientMetadata,
      oauth.ClientSecretPost(this.clientSecret),
      codeGrantParams,
      redirectUri.toString(),
      transactionState.codeVerifier,
      {
        [oauth.customFetch]: this.fetch,
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
      const { user } = await this.beforeSessionSaved(session)
      session.user = user || {}
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
          error: "You are not authenticated.",
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
          error: error.message,
          error_code: error.code,
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
      return [new MissingRefreshToken(), null]
    }

    // the access token has expired and we have a refresh token
    if (tokenSet.refreshToken && tokenSet.expiresAt <= Date.now() / 1000) {
      const [discoveryError, authorizationServerMetadata] =
        await this.discoverAuthorizationServerMetadata()

      if (discoveryError) {
        return [discoveryError, null]
      }

      const refreshTokenRes = await oauth.refreshTokenGrantRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        oauth.ClientSecretPost(this.clientSecret),
        tokenSet.refreshToken,
        {
          [oauth.customFetch]: this.fetch,
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
        return [
          new RefreshTokenGrantError({
            cause: new OAuth2Error({
              code: e.error,
              message: e.error_description,
            }),
          }),
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
        })
        .then((response) => oauth.processDiscoveryResponse(issuer, response))

      return [null, authorizationServerMetadata]
    } catch (e) {
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
}
