import type { IncomingMessage, ServerResponse } from "node:http"
import { cookies } from "next/headers"
import { NextRequest, NextResponse } from "next/server"
import { NextApiRequest, NextApiResponse } from "next/types"

import { AccessTokenError, AccessTokenErrorCode } from "../errors"
import { SessionData } from "../types"
import {
  AuthClient,
  AuthorizationParameters,
  BeforeSessionSavedHook,
  OnCallbackHook,
  RoutesOptions,
} from "./auth-client"
import { RequestCookies, ResponseCookies } from "./cookies"
import {
  AbstractSessionStore,
  SessionConfiguration,
  SessionDataStore,
} from "./session/abstract-session-store"
import { StatefulSessionStore } from "./session/stateful-session-store"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { TransactionStore } from "./transaction-store"

interface Auth0ClientOptions {
  // authorization server configuration
  /**
   * The Auth0 domain for the tenant (e.g.: `example.us.auth0.com`).
   *
   * If it's not specified, it will be loaded from the `AUTH0_DOMAIN` environment variable.
   */
  domain?: string
  /**
   * The Auth0 client ID.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_ID` environment variable.
   */
  clientId?: string
  /**
   * The Auth0 client secret.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_SECRET` environment variable.
   */
  clientSecret?: string
  /**
   * Additional parameters to send to the `/authorize` endpoint.
   */
  authorizationParameters?: AuthorizationParameters
  /**
   * If enabled, the SDK will use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.
   */
  pushedAuthorizationRequests?: boolean
  /**
   * Private key for use with `private_key_jwt` clients.
   * This should be a string that is the contents of a PEM file or a CryptoKey.
   */
  clientAssertionSigningKey?: string | CryptoKey
  /**
   * The algorithm used to sign the client assertion JWT.
   * Uses one of `token_endpoint_auth_signing_alg_values_supported` if not specified.
   * If the Authorization Server discovery document does not list `token_endpoint_auth_signing_alg_values_supported`
   * this property will be required.
   */
  clientAssertionSigningAlg?: string

  // application configuration
  /**
   * The URL of your application (e.g.: `http://localhost:3000`).
   *
   * If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.
   */
  appBaseUrl?: string
  /**
   * A 32-byte, hex-encoded secret used for encrypting cookies.
   *
   * If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.
   */
  secret?: string
  /**
   * The path to redirect the user to after successfully authenticating. Defaults to `/`.
   */
  signInReturnToPath?: string

  // session configuration
  /**
   * Configure the session timeouts and whether to use rolling sessions or not.
   *
   * See [Session configuration](https://github.com/auth0/nextjs-auth0#session-configuration) for additional details.
   */
  session?: SessionConfiguration

  // hooks
  /**
   * A method to manipulate the session before persisting it.
   *
   * See [beforeSessionSaved](https://github.com/auth0/nextjs-auth0#beforesessionsaved) for additional details
   */
  beforeSessionSaved?: BeforeSessionSavedHook
  /**
   * A method to handle errors or manage redirects after attempting to authenticate.
   *
   * See [onCallback](https://github.com/auth0/nextjs-auth0#oncallback) for additional details
   */
  onCallback?: OnCallbackHook

  // provide a session store to persist sessions in your own data store
  /**
   * A custom session store implementation used to persist sessions to a data store.
   *
   * See [Database sessions](https://github.com/auth0/nextjs-auth0#database-sessions) for additional details.
   */
  sessionStore?: SessionDataStore

  /**
   * Configure the paths for the authentication routes.
   *
   * See [Custom routes](https://github.com/auth0/nextjs-auth0#custom-routes) for additional details.
   */
  routes?: RoutesOptions

  /**
   * Allow insecure requests to be made to the authorization server. This can be useful when testing
   * with a mock OIDC provider that does not support TLS, locally.
   * This option can only be used when NODE_ENV is not set to `production`.
   */
  allowInsecureRequests?: boolean
}

type PagesRouterRequest = IncomingMessage | NextApiRequest
type PagesRouterResponse = ServerResponse<IncomingMessage> | NextApiResponse

export class Auth0Client {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore
  private authClient: AuthClient

  constructor(options: Auth0ClientOptions = {}) {
    const domain = (options.domain || process.env.AUTH0_DOMAIN) as string
    const clientId = (options.clientId || process.env.AUTH0_CLIENT_ID) as string
    const clientSecret = (options.clientSecret ||
      process.env.AUTH0_CLIENT_SECRET) as string

    const appBaseUrl = (options.appBaseUrl ||
      process.env.APP_BASE_URL) as string
    const secret = (options.secret || process.env.AUTH0_SECRET) as string

    const clientAssertionSigningKey =
      options.clientAssertionSigningKey ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY
    const clientAssertionSigningAlg =
      options.clientAssertionSigningAlg ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG

    const cookieOptions = {
      secure: false,
    }
    if (appBaseUrl) {
      const { protocol } = new URL(appBaseUrl)
      if (protocol === "https:") {
        cookieOptions.secure = true
      }
    }

    this.transactionStore = new TransactionStore({
      ...options.session,
      secret,
      cookieOptions,
    })

    this.sessionStore = options.sessionStore
      ? new StatefulSessionStore({
          ...options.session,
          secret,
          store: options.sessionStore,
          cookieOptions,
        })
      : new StatelessSessionStore({
          ...options.session,
          secret,
          cookieOptions,
        })

    this.authClient = new AuthClient({
      transactionStore: this.transactionStore,
      sessionStore: this.sessionStore,

      domain,
      clientId,
      clientSecret,
      clientAssertionSigningKey,
      clientAssertionSigningAlg,
      authorizationParameters: options.authorizationParameters,
      pushedAuthorizationRequests: options.pushedAuthorizationRequests,

      appBaseUrl,
      secret,
      signInReturnToPath: options.signInReturnToPath,

      beforeSessionSaved: options.beforeSessionSaved,
      onCallback: options.onCallback,

      routes: options.routes,

      allowInsecureRequests: options.allowInsecureRequests,
    })
  }

  /**
   * middleware mounts the SDK routes to run as a middleware function.
   */
  middleware(req: NextRequest): Promise<NextResponse> {
    return this.authClient.handler.bind(this.authClient)(req)
  }

  /**
   * getSession returns the session data for the current request.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the **App Router**.
   */
  async getSession(): Promise<SessionData | null>

  /**
   * getSession returns the session data for the current request.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getSession(
    req: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null>

  /**
   * getSession returns the session data for the current request.
   */
  async getSession(
    req?: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null> {
    if (req) {
      // middleware usage
      if (req instanceof NextRequest) {
        return this.sessionStore.get(req.cookies)
      }

      // pages router usage
      return this.sessionStore.get(this.createRequestCookies(req))
    }

    // app router usage: Server Components, Server Actions, Route Handlers
    return this.sessionStore.get(await cookies())
  }

  /**
   * getAccessToken returns the access token.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the **App Router**.
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessToken(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  async getAccessToken(): Promise<{ token: string; expiresAt: number }>

  /**
   * getAccessToken returns the access token.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getAccessToken(
    req: PagesRouterRequest | NextRequest,
    res: PagesRouterResponse | NextResponse
  ): Promise<{ token: string; expiresAt: number }>

  /**
   * getAccessToken returns the access token.
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessToken(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  async getAccessToken(
    req?: PagesRouterRequest | NextRequest,
    res?: PagesRouterResponse | NextResponse
  ): Promise<{ token: string; expiresAt: number }> {
    let session: SessionData | null = null

    if (req) {
      if (req instanceof NextRequest) {
        // middleware usage
        session = await this.sessionStore.get(req.cookies)
      } else {
        // pages router usage
        session = await this.sessionStore.get(this.createRequestCookies(req))
      }
    } else {
      // app router usage: Server Components, Server Actions, Route Handlers
      session = await this.sessionStore.get(await cookies())
    }

    if (!session) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      )
    }

    const [error, tokenSet] = await this.authClient.getTokenSet(
      session.tokenSet
    )
    if (error) {
      throw error
    }

    // update the session with the new token set, if necessary
    if (
      tokenSet.accessToken !== session.tokenSet.accessToken ||
      tokenSet.expiresAt !== session.tokenSet.expiresAt ||
      tokenSet.refreshToken !== session.tokenSet.refreshToken
    ) {
      if (req && res) {
        if (req instanceof NextRequest && res instanceof NextResponse) {
          // middleware usage
          await this.sessionStore.set(req.cookies, res.cookies, {
            ...session,
            tokenSet,
          })
        } else {
          // pages router usage
          const resHeaders = new Headers()
          const resCookies = new ResponseCookies(resHeaders)
          const pagesRouterRes = res as PagesRouterResponse

          await this.sessionStore.set(
            this.createRequestCookies(req as PagesRouterRequest),
            resCookies,
            {
              ...session,
              tokenSet,
            }
          )

          for (const [key, value] of resHeaders.entries()) {
            pagesRouterRes.setHeader(key, value)
          }
        }
      } else {
        // app router usage: Server Components, Server Actions, Route Handlers
        try {
          await this.sessionStore.set(await cookies(), await cookies(), {
            ...session,
            tokenSet,
          })
        } catch (e) {
          if (process.env.NODE_ENV === "development") {
            console.warn(
              "Failed to persist the updated token set. `getAccessToken()` was likely called from a Server Component which cannot set cookies."
            )
          }
        }
      }
    }

    return {
      token: tokenSet.accessToken,
      expiresAt: tokenSet.expiresAt,
    }
  }

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes, and middleware in the **Pages Router**.
   */
  async updateSession(
    req: PagesRouterRequest | NextRequest,
    res: PagesRouterResponse | NextResponse,
    session: SessionData
  ): Promise<void>

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   *
   * This method can be used in Server Actions and Route Handlers in the **App Router**.
   */
  async updateSession(session: SessionData): Promise<void>

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   */
  async updateSession(
    reqOrSession: PagesRouterRequest | NextRequest | SessionData,
    res?: PagesRouterResponse | NextResponse,
    sessionData?: SessionData
  ) {
    if (!res) {
      // app router: Server Actions, Route Handlers
      const existingSession = await this.getSession()

      if (!existingSession) {
        throw new Error("The user is not authenticated.")
      }

      const updatedSession = reqOrSession as SessionData
      if (!updatedSession) {
        throw new Error("The session data is missing.")
      }

      await this.sessionStore.set(await cookies(), await cookies(), {
        ...updatedSession,
        internal: {
          ...existingSession.internal,
        },
      })
    } else {
      const req = reqOrSession as PagesRouterRequest | NextRequest

      if (!sessionData) {
        throw new Error("The session data is missing.")
      }

      if (req instanceof NextRequest && res instanceof NextResponse) {
        // middleware usage
        const existingSession = await this.getSession(req)

        if (!existingSession) {
          throw new Error("The user is not authenticated.")
        }

        await this.sessionStore.set(req.cookies, res.cookies, {
          ...sessionData,
          internal: {
            ...existingSession.internal,
          },
        })
      } else {
        // pages router usage
        const existingSession = await this.getSession(req as PagesRouterRequest)

        if (!existingSession) {
          throw new Error("The user is not authenticated.")
        }

        const resHeaders = new Headers()
        const resCookies = new ResponseCookies(resHeaders)
        const updatedSession = sessionData as SessionData
        const reqCookies = this.createRequestCookies(req as PagesRouterRequest)
        const pagesRouterRes = res as PagesRouterResponse

        await this.sessionStore.set(reqCookies, resCookies, {
          ...updatedSession,
          internal: {
            ...existingSession.internal,
          },
        })

        for (const [key, value] of resHeaders.entries()) {
          pagesRouterRes.setHeader(key, value)
        }
      }
    }
  }

  private createRequestCookies(req: PagesRouterRequest) {
    const headers = new Headers()

    for (const key in req.headers) {
      if (Array.isArray(req.headers[key])) {
        for (const value of req.headers[key]) {
          headers.append(key, value)
        }
      } else {
        headers.append(key, req.headers[key] ?? "")
      }
    }

    return new RequestCookies(headers)
  }
}
