import type { ParsedUrlQuery } from "querystring";
import { NextRequest, NextResponse } from "next/server.js";
import { NextApiHandler, NextApiRequest, NextApiResponse } from "next/types.js";

import {
  AccessTokenForConnectionError,
  TokenRevocationError
} from "../errors/index.js";
import {
  AccessTokenForConnectionOptions,
  AnonymousSession,
  BackchannelAuthenticationOptions,
  BackchannelAuthenticationResponse,
  ConnectAccountOptions,
  ConnectedAccount,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse,
  DisconnectAccountOptions,
  GetAccessTokenOptions,
  SessionData,
  SessionTransferTokenOptions,
  SessionTransferTokenResult,
  StartEnterpriseLoginOptions,
  StartInteractiveLoginOptions
} from "../types/index.js";
import {
  AccessTokenFactory,
  CustomFetchImpl,
  Fetcher
} from "./fetcher/fetcher.js";
import * as withApiAuthRequired from "./helpers/with-api-auth-required.js";
import {
  AppRouterPageRoute,
  AppRouterPageRouteOpts,
  PageRoute,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouterOptions
} from "./helpers/with-page-auth-required.js";
import { ServerMfaClient } from "./mfa/server-mfa-client.js";
import { ServerPasskeyClient } from "./passkey/server-passkey-client.js";
import { ServerPasswordlessClient } from "./passwordless/server-passwordless-client.js";
import type {
  Auth0ClientOptions,
  PagesRouterRequest,
  PagesRouterResponse
} from "./types/index.js";

export class Auth0Client {
  #options: Auth0ClientOptions;

  constructor(options: Auth0ClientOptions = {}) {
    this.#options = options;
  }

  /**
   * middleware mounts the SDK routes to run as a middleware function.
   */
  async middleware(req: Request | NextRequest): Promise<NextResponse> {
    throw new Error("not implemented");
  }

  /**
   * getSession returns the session data for the current request.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the **App Router**.
   */
  async getSession(): Promise<SessionData | null>;

  /**
   * getSession returns the session data for the current request.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getSession(
    req: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null>;

  /**
   * getSession returns the session data for the current request.
   */
  async getSession(
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<SessionData | null> {
    throw new Error("not implemented");
  }

  /**
   * getAnonymousSession returns the current anonymous session, or null when there is
   * none (or the feature is disabled). It never throws for a missing, malformed, or
   * expired cookie. Mirrors {@link getSession}.
   *
   * Use in Server Components, Server Actions, and Route Handlers in the **App Router**.
   */
  async getAnonymousSession(): Promise<AnonymousSession | null>;

  /**
   * getAnonymousSession returns the current anonymous session, or null when there is none.
   *
   * Use in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getAnonymousSession(
    req: PagesRouterRequest | NextRequest
  ): Promise<AnonymousSession | null>;

  async getAnonymousSession(
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<AnonymousSession | null> {
    throw new Error("not implemented");
  }

  /**
   * createAnonymousSession creates a fresh anonymous session, persists the cookie, and
   * returns the session. Throws `AnonymousSessionError` on any authorization-server error.
   *
   * Metadata is set once at creation and cannot be changed after (CASCADE-v2 M2).
   * Validates metadata against 1KB cap before network call; oversize → metadata_too_large.
   *
   * **App Router only (creation).** Creating an anonymous session requires writing a
   * Set-Cookie header onto a `NextResponse`, which is only possible in the App Router
   * (Server Actions and Route Handlers). Use in Server Actions (zero-arg form).
   *
   * For reading an existing session in any context, use {@link getAnonymousSession},
   * which is read-only and never creates or sets a cookie.
   */
  async createAnonymousSession(options?: {
    metadata?: Record<string, unknown>;
    audience?: string;
    scope?: string;
  }): Promise<AnonymousSession>;

  /**
   * createAnonymousSession creates a fresh anonymous session with optional creation-time metadata
   * and persists the cookie onto the passed response.
   *
   * Metadata is set once at creation and cannot be changed after (CASCADE-v2 M2).
   * Validates metadata against 1KB cap before network call; oversize → metadata_too_large.
   *
   * Use in Route Handlers (**App Router** only — `res` must be a `NextResponse`).
   * The response writes cookies via `res.cookies`, which requires a `NextResponse`; a
   * Pages Router `ServerResponse` / `NextApiResponse` does not have a `cookies` jar.
   * Creation is App Router only for now. {@link getAnonymousSession} is read-only and
   * never creates or sets a cookie, so it cannot be used to create a session in the
   * Pages Router.
   */
  async createAnonymousSession(
    req: PagesRouterRequest | NextRequest,
    res: NextResponse,
    options?: {
      metadata?: Record<string, unknown>;
      audience?: string;
      scope?: string;
    }
  ): Promise<AnonymousSession>;

  async createAnonymousSession(
    req?:
      | Request
      | PagesRouterRequest
      | NextRequest
      | {
          metadata?: Record<string, unknown>;
          audience?: string;
          scope?: string;
        },
    res?: NextResponse,
    options?: {
      metadata?: Record<string, unknown>;
      audience?: string;
      scope?: string;
    }
  ): Promise<AnonymousSession> {
    throw new Error("not implemented");
  }

  /**
   * getAccessToken returns the access token.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the **App Router**.
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessToken(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  /**
   * @param options Optional configuration for getting the access token.
   * @param options.refresh Force a refresh of the access token.
   */
  async getAccessToken(options?: GetAccessTokenOptions): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }>;

  /**
   * getAccessToken returns the access token.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   *
   * @param req The request object.
   * @param res The response object.
   * @param options Optional configuration for getting the access token.
   * @param options.refresh Force a refresh of the access token.
   */
  async getAccessToken(
    req: PagesRouterRequest | NextRequest,
    res: PagesRouterResponse | NextResponse,
    options?: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }>;

  /**
   * getAccessToken returns the access token.
   *
   * Please note: If you are passing audience, ensure that the used audiences and scopes are
   * part of the Application's Refresh Token Policies in Auth0 when configuring Multi-Resource Refresh Tokens (MRRT).
   * {@link https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token | See Auth0 Documentation on Multi-resource Refresh Tokens}
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessToken(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  async getAccessToken(
    arg1?: PagesRouterRequest | NextRequest | GetAccessTokenOptions,
    arg2?: PagesRouterResponse | NextResponse,
    arg3?: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }> {
    throw new Error("not implemented");
  }

  /**
   * Retrieves an access token for a connection.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the **App Router**.
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessTokenForConnection()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessTokenForConnection(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions
  ): Promise<{ token: string; expiresAt: number }>;

  /**
   * Retrieves an access token for a connection.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions,
    req: PagesRouterRequest | NextRequest | Request | undefined,
    res: PagesRouterResponse | NextResponse | undefined
  ): Promise<{ token: string; expiresAt: number }>;

  /**
   * Retrieves an access token for a connection.
   *
   * This method attempts to obtain an access token for a specified connection.
   * It first checks if a session exists, either from the provided request or from cookies.
   * If no session is found, it throws a `AccessTokenForConnectionError` indicating
   * that the user does not have an active session.
   *
   * @param {AccessTokenForConnectionOptions} options - Options for retrieving an access token for a connection.
   * @param {PagesRouterRequest | NextRequest} [req] - An optional request object from which to extract session information.
   * @param {PagesRouterResponse | NextResponse} [res] - An optional response object from which to extract session information.
   *
   * @throws {AccessTokenForConnectionError} If the user does not have an active session.
   * @throws {Error} If there is an error during the token exchange process.
   *
   * @returns {Promise<{ token: string; expiresAt: number; scope?: string }} An object containing the access token and its expiration time.
   */
  async getAccessTokenForConnection(
    options: AccessTokenForConnectionOptions,
    req?: PagesRouterRequest | NextRequest | Request,
    res?: PagesRouterResponse | NextResponse
  ): Promise<{ token: string; expiresAt: number; scope?: string }> {
    throw new Error("not implemented");
  }

  /**
   * Exchanges an external token for Auth0 tokens using Custom Token Exchange (RFC 8693).
   *
   * This is a server-only method that does NOT modify the session.
   * The returned tokens can be used independently or stored by the developer.
   *
   * **Note**: CTE tokens are not cached. The caller is responsible for token storage if needed.
   *
   * This method can be used in Server Actions, Route Handlers, and API routes.
   *
   * @param options - The custom token exchange options
   * @returns The token exchange response containing access token and optionally id/refresh tokens
   * @throws {CustomTokenExchangeError} If validation fails or the exchange request fails
   *
   * @example
   * ```typescript
   * const result = await auth0.customTokenExchange({
   *   subjectToken: legacyIdToken,
   *   subjectTokenType: 'urn:acme:legacy-token',
   *   audience: 'https://api.example.com',
   *   scope: 'read:data'
   * });
   *
   * console.log(result.accessToken);
   * ```
   *
   * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Auth0 CTE Documentation}
   */
  async customTokenExchange(
    options: CustomTokenExchangeOptions
  ): Promise<CustomTokenExchangeResponse> {
    throw new Error("not implemented");
  }

  /**
   * Revokes the refresh token stored in the current session at the Auth0
   * `/oauth/revoke` endpoint (RFC 7009).
   *
   * Auth0 will also invalidate all access tokens issued under the same
   * authorization grant — any subsequent API calls using those tokens will
   * fail. The local session cookie is not cleared — use `handleLogout`
   * (which already revokes on logout) for a full logout.
   *
   * @param options For the Pages Router, pass the request object so the session can be read.
   *
   * @throws {TokenRevocationError} If no session or refresh token exists, or the revocation request fails.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc7009 RFC 7009 Token Revocation}
   */
  async revokeRefreshToken(options?: {
    req?: PagesRouterRequest | NextRequest;
  }): Promise<void> {
    throw new Error("not implemented");
  }

  /**
   * Requests a Session Transfer Token (STT) that lets an authenticated agent
   * establish a web session **as a customer** in a target app — without the customer's password.
   *
   * This method can be used in Server Components, Server Actions, and Route Handlers in the
   * **App Router**.
   *
   * NOTE: Server Components cannot set cookies. If the actor's ID token needs a silent refresh
   * (see below), calling this from a Server Component will refresh the token but the updated
   * token set will not be persisted. Prefer calling this from a Route Handler or Server Action.
   *
   * The SDK fills in `audience`, `grant_type`, `actor_token`, and `actor_token_type` automatically.
   * The actor defaults to the agent session's ID token. If the ID token is expired and a
   * refresh token is available the SDK silently refreshes the session first — the refreshed
   * token set is persisted back to the session cookie (through the `beforeSessionSaved` hook,
   * if configured), since refresh token rotation invalidates the old refresh token still held
   * in the session. If no refresh token is available this throws `ACTOR_UNAVAILABLE`. If the
   * refresh itself requires MFA step-up, this throws `MfaRequiredError`.
   *
   * Use the result with `buildSessionTransferRedirect` to redirect the agent's browser
   * to the target app's login URL.
   *
   * **The returned STT is one-shot (~60s) and must never be cached.**
   *
   * @example
   * ```typescript
   * // app/api/stt/route.ts — App Router Route Handler
   * const result = await auth0.requestSessionTransferToken({
   *   subjectToken: mySubjectToken,
   *   subjectTokenType: "urn:acme:subject",
   *   reason: "Investigating ticket #1234"
   * });
   * return auth0.buildSessionTransferRedirect("https://app.example.com/auth/login", result);
   * ```
   */
  async requestSessionTransferToken(
    options: SessionTransferTokenOptions
  ): Promise<SessionTransferTokenResult>;

  /**
   * Requests a Session Transfer Token (STT) that lets an authenticated agent
   * establish a web session **as a customer** in a target app — without the customer's password.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes in the
   * **Pages Router**.
   *
   * @param req The request object.
   * @param res The response object.
   * @param options STT exchange options.
   *
   * @example
   * ```typescript
   * // pages/api/stt.ts — Pages Router API route
   * const result = await auth0.requestSessionTransferToken(req, res, {
   *   subjectToken: mySubjectToken,
   *   subjectTokenType: "urn:acme:subject"
   * });
   * ```
   */
  async requestSessionTransferToken(
    req: PagesRouterRequest | NextRequest,
    res: PagesRouterResponse | NextResponse,
    options: SessionTransferTokenOptions
  ): Promise<SessionTransferTokenResult>;

  async requestSessionTransferToken(
    arg1: SessionTransferTokenOptions | PagesRouterRequest | NextRequest,
    arg2?: PagesRouterResponse | NextResponse,
    arg3?: SessionTransferTokenOptions
  ): Promise<SessionTransferTokenResult> {
    throw new Error("not implemented");
  }

  /**
   * Builds a `NextResponse` redirect that carries the STT to the target app's login route.
   *
   * Returns a redirect to `targetLoginUrl?session_transfer_token=<encoded>(&organization=…)`.
   * Pure URL builder — no network call, nothing written to session.
   *
   * @param targetLoginUrl - The target app's login URL. Must be a trusted, app-controlled value.
   * @param result - The `SessionTransferTokenResult` from `requestSessionTransferToken`
   * @param opts - Optional: `organization` to append (same value passed to `requestSessionTransferToken`)
   *
   * @example
   * ```typescript
   * const result = await auth0.requestSessionTransferToken({ subjectToken, subjectTokenType });
   * return auth0.buildSessionTransferRedirect("https://app.example.com/auth/login", result);
   * ```
   */
  buildSessionTransferRedirect(
    targetLoginUrl: string,
    result: SessionTransferTokenResult,
    opts?: { organization?: string }
  ): NextResponse {
    throw new Error("not implemented");
  }

  /**
   * MFA API for server-side operations.
   *
   * Provides access to MFA methods that require encrypted mfa_token from MfaRequiredError:
   * - getAuthenticators: List enrolled MFA factors
   * - challenge: Initiate MFA challenge (OTP/OOB)
   * - verify: Complete MFA verification
   *
   * @example Handling MFA required scenario
   * ```typescript
   * try {
   *   const { token } = await auth0.getAccessToken({ audience: 'https://api.example.com' });
   * } catch (error) {
   *   if (error instanceof MfaRequiredError) {
   *     // Get available authenticators
   *     const authenticators = await auth0.mfa.getAuthenticators({
   *       mfaToken: error.mfa_token
   *     });
   *
   *     // Initiate challenge
   *     const challenge = await auth0.mfa.challenge({
   *       mfaToken: error.mfa_token,
   *       challengeType: 'otp',
   *       authenticatorId: authenticators[0].id
   *     });
   *
   *     // Verify code — tokens stored in session cookie, not in response body
   *     await auth0.mfa.verify({
   *       mfaToken: error.mfa_token,
   *       otp: '123456'
   *     });
   *     // Retrieve the access token from the session after verify
   *     const token = await auth0.getAccessToken();
   *   }
   * }
   * ```
   */
  get mfa(): ServerMfaClient {
    throw new Error("not implemented");
  }

  /**
   * Access server-side passwordless authentication operations.
   * Use `auth0.passwordless.start()` to send an OTP, and
   * `auth0.passwordless.verify()` to verify the code and log the user in.
   */
  get passwordless(): ServerPasswordlessClient {
    throw new Error("not implemented");
  }

  /**
   * Access server-side passkey (WebAuthn) authentication and enrollment operations.
   *
   * Authentication: `auth0.passkey.register()`, `auth0.passkey.challenge()`, `auth0.passkey.getToken()`
   * Enrollment: `auth0.passkey.enrollmentChallenge()`, `auth0.passkey.enrollmentVerify()`
   */
  get passkey(): ServerPasskeyClient {
    throw new Error("not implemented");
  }

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   *
   * This method can be used in middleware and `getServerSideProps`, API routes, and middleware in the **Pages Router**.
   */
  async updateSession(
    req: PagesRouterRequest | NextRequest | Request,
    res: PagesRouterResponse | NextResponse | Response,
    session: SessionData
  ): Promise<void>;

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   *
   * This method can be used in Server Actions and Route Handlers in the **App Router**.
   */
  async updateSession(session: SessionData): Promise<void>;

  /**
   * updateSession updates the session of the currently authenticated user. If the user does not have a session, an error is thrown.
   */
  async updateSession(
    reqOrSession: PagesRouterRequest | NextRequest | Request | SessionData,
    res?: PagesRouterResponse | NextResponse | Response,
    sessionData?: SessionData
  ): Promise<void> {
    throw new Error("not implemented");
  }

  /**
   * startInteractiveLogin redirects the user to the authorization server to log in.
   *
   * Pass the request when one is available (Route Handlers, middleware, the Pages
   * Router). The request is what lets the SDK read this browser's cookies, which
   * is how an active anonymous session is linked to the login transaction. In a
   * Server Action, where there is no request object, cookies are read through
   * `next/headers` instead.
   */
  async startInteractiveLogin(
    options: StartInteractiveLoginOptions = {},
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<NextResponse> {
    throw new Error("not implemented");
  }

  /**
   * Login entry point for {@link Auth0Client.enterpriseConnect} mode.
   *
   * Runs Home Realm Discovery on the email domain. Returns a `NextResponse`
   * redirect (with `login_hint` set) when the domain is federated, or `null`
   * when it is not — allowing the caller to fall back to its own login.
   *
   * Must be called from a Route Handler (not a Server Action) so the transaction
   * cookie is returned to the browser.
   *
   * @param options - `email` is required; `authorizationParameters`, `returnTo`,
   *   and `challengeMode` are forwarded to the underlying login.
   * @returns Redirect response for a federated domain, or `null`.
   *
   * @example
   * ```ts
   * // app/api/login/route.ts
   * export async function POST(req: NextRequest) {
   *   const email = String((await req.formData()).get("email") ?? "");
   *   const res = await auth0.startEnterpriseLogin({ email, returnTo: "/dashboard" });
   *   if (res) {
   *     const redirect = NextResponse.redirect(res.headers.get("location")!, 303);
   *     for (const c of res.cookies.getAll()) redirect.cookies.set(c);
   *     return redirect;
   *   }
   *   return NextResponse.redirect(new URL("/existing-login", req.url));
   * }
   * ```
   *
   * @see [Enterprise Connect](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#enterprise-connect-b2b-integration) for the full flow.
   */
  async startEnterpriseLogin(
    options: StartEnterpriseLoginOptions
  ): Promise<NextResponse | null> {
    throw new Error("not implemented");
  }

  /**
   * Authenticates using Client-Initiated Backchannel Authentication and returns the token set and optionally the ID token claims and authorization details.
   *
   * This method will initialize the backchannel authentication process with Auth0, and poll the token endpoint until the authentication is complete.
   *
   * Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
   * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
   */
  async getTokenByBackchannelAuth(
    options: BackchannelAuthenticationOptions
  ): Promise<BackchannelAuthenticationResponse> {
    throw new Error("not implemented");
  }

  /**
   * Initiates the Connect Account flow to connect a third-party account to the user's profile.
   *
   * This method can be used in Server Actions and Route Handlers in the **App Router**.
   */
  async connectAccount(options: ConnectAccountOptions): Promise<NextResponse>;

  /**
   * Initiates the Connect Account flow to connect a third-party account to the user's profile.
   *
   * Pass the `req` object when calling from middleware, or when `APP_BASE_URL`
   * is configured dynamically (as an array of allowed origins), so the redirect
   * and session are resolved from the request context. The returned
   * `NextResponse` carries the redirect and the transaction cookies.
   */
  async connectAccount(
    options: ConnectAccountOptions,
    req: NextRequest | Request
  ): Promise<NextResponse>;

  /**
   * Initiates the Connect Account flow to connect a third-party account to the user's profile.
   * If the user does not have an active session, a `ConnectAccountError` is thrown.
   *
   * This method first attempts to obtain an access token with the `create:me:connected_accounts` scope
   * for the My Account API to create a connected account for the user.
   *
   * The user will then be redirected to authorize the connection with the third-party provider.
   *
   * Pass the `req` object when calling from middleware or when `APP_BASE_URL` is
   * configured dynamically (as an array of allowed origins), so the redirect and
   * session are resolved from the request context. In App Router Server Actions
   * and Route Handlers with a static `APP_BASE_URL`, omit it. Because this
   * returns a redirect `NextResponse` (rather than writing to a passed-in
   * response), a Pages Router `ServerResponse` is not accepted here; forward the
   * returned response's `Location` and `Set-Cookie` headers onto your response.
   *
   * Minting the My Account access token can rotate the refresh token. On success
   * that rotation is written onto the returned redirect response's cookies, so
   * forwarding its `Set-Cookie` headers (as above) persists it. On the error path
   * there is no response to attach to, so the rotation is persisted best-effort
   * via ambient cookies, which a React Server Component cannot write; prefer a
   * Route Handler, Server Action, API route, or middleware so a failed connect
   * does not drop the rotated token and log the user out on the next refresh.
   *
   * You must enable `Offline Access` from the Connection Permissions settings to be able to use the connection with Connected Accounts.
   */
  async connectAccount(
    options: ConnectAccountOptions,
    req?: NextRequest | Request
  ): Promise<NextResponse> {
    throw new Error("not implemented");
  }

  /**
   * Disconnects (unlinks) all connected accounts for the given connection.
   *
   * This method can be used in Server Actions and Route Handlers in the **App Router**.
   */
  async disconnectAccount(options: DisconnectAccountOptions): Promise<void>;

  /**
   * Disconnects (unlinks) all connected accounts for the given connection.
   *
   * This method can be used in middleware and API routes in the **Pages Router**.
   */
  async disconnectAccount(
    options: DisconnectAccountOptions,
    req: PagesRouterRequest | NextRequest | Request,
    res: PagesRouterResponse | NextResponse
  ): Promise<void>;

  /**
   * Disconnects (unlinks) all connected accounts for the given connection.
   *
   * This revokes the connection server-side via the My Account API and removes
   * the corresponding cached connection tokens from the session so they are not
   * re-assembled on subsequent reads.
   *
   * If the user does not have an active session, a `ConnectedAccountsError` is
   * thrown with code `MISSING_SESSION`. If the server-side revoke fails, a
   * `ConnectedAccountsError` with code `FAILED_TO_DELETE` is thrown.
   *
   * **Do not call this from a React Server Component.** Minting the My Account
   * access token can rotate the refresh token, and Server Components cannot
   * write cookies, so the write is silently dropped (only warned in
   * `NODE_ENV=development`). On the next request the browser still sends the old
   * refresh token, which the authorization server rejects as replay and logs the
   * user out. Call from a Route Handler, Server Action, API route, or middleware.
   *
   * Partial-failure contract: the local cached connection tokens
   * (`connectionTokenSets`) for the connection are pruned from the session
   * regardless of whether the server-side revoke succeeded, and any rotated
   * refresh token is persisted, before the error (if any) is rethrown. So on a
   * `FAILED_TO_DELETE` the server-side state may be partially disconnected while
   * the local state is fully cleaned; a subsequent `getAccessTokenForConnection`
   * would fail-exchange and prune anyway.
   *
   * In the Pages Router (or middleware), pass the `req` and `res` objects so the
   * pruned session can be persisted to the response cookies. In App Router Server
   * Actions and Route Handlers, omit them.
   *
   * Note: disconnect is connection-scoped. All accounts connected through the
   * given connection are disconnected. Per-account disconnect is not currently
   * supported because the My Account API keys connected accounts by id and does
   * not expose the login hint used to disambiguate multiple accounts on the same
   * connection.
   */
  async disconnectAccount(
    options: DisconnectAccountOptions,
    req?: PagesRouterRequest | NextRequest | Request,
    res?: PagesRouterResponse | NextResponse
  ): Promise<void> {
    throw new Error("not implemented");
  }

  /**
   * Lists the connected accounts for the current user from the My Account API.
   *
   * This method can be used in Server Actions and Route Handlers in the **App Router**.
   */
  async getConnectedAccounts(): Promise<ConnectedAccount[]>;

  /**
   * Lists the connected accounts for the current user from the My Account API.
   *
   * This method can be used in middleware and API routes in the **Pages Router**.
   */
  async getConnectedAccounts(
    req: PagesRouterRequest | NextRequest | Request,
    res: PagesRouterResponse | NextResponse
  ): Promise<ConnectedAccount[]>;

  /**
   * Lists the connected accounts for the current user from the My Account API.
   *
   * The My Account API is the source of truth, so this also reconciles the
   * session: any locally cached connection tokens (`connectionTokenSets`) whose
   * connection is no longer present server-side are pruned, so they are not
   * re-assembled into the session on subsequent reads.
   *
   * **Do not call this from a React Server Component.** Minting the My Account
   * access token can rotate the refresh token, and Server Components cannot
   * write cookies — the write is silently dropped (only warned in
   * `NODE_ENV=development`). On the next request the browser still sends the
   * old refresh token, which the authorization server rejects as replay and
   * logs the user out. Call from a Route Handler, Server Action, API route,
   * or middleware. In the Pages Router (or middleware), pass the `req` and
   * `res` objects so the reconciled session can be persisted to the response
   * cookies.
   *
   * If the user does not have an active session, a `ConnectedAccountsError` is thrown.
   *
   * Note: reconciliation is connection-scoped. If a user has multiple accounts
   * on the same connection and only some are disconnected server-side, the
   * connection still appears in the list, so the local tokens are retained. This
   * mirrors the connection-scoped behaviour of {@link disconnectAccount}.
   */
  async getConnectedAccounts(
    req?: PagesRouterRequest | NextRequest | Request,
    res?: PagesRouterResponse | NextResponse
  ): Promise<ConnectedAccount[]> {
    throw new Error("not implemented");
  }

  // Pages Router overload - no arguments
  withPageAuthRequired(): PageRoute<{ [key: string]: any }, ParsedUrlQuery>;
  // Pages Router overload - with options
  withPageAuthRequired<
    P extends { [key: string]: any } = { [key: string]: any },
    Q extends ParsedUrlQuery = ParsedUrlQuery
  >(opts: WithPageAuthRequiredPageRouterOptions<P, Q>): PageRoute<P, Q>;
  // App Router overload - with component function
  withPageAuthRequired<
    P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
  >(
    fn: AppRouterPageRoute<P>,
    opts?: WithPageAuthRequiredAppRouterOptions<P>
  ): AppRouterPageRoute<P>;
  // Implementation
  withPageAuthRequired(
    fnOrOpts?: WithPageAuthRequiredPageRouterOptions | AppRouterPageRoute,
    opts?: WithPageAuthRequiredAppRouterOptions
  ): any {
    throw new Error("not implemented");
  }

  withApiAuthRequired(
    apiRoute: withApiAuthRequired.AppRouteHandlerFn | NextApiHandler
  ): (
    req: NextRequest | NextApiRequest,
    resOrParams: withApiAuthRequired.AppRouteHandlerFnContext | NextApiResponse
  ) => unknown {
    throw new Error("not implemented");
  }

  /**
   * Creates a configured Fetcher instance for making authenticated API requests.
   *
   * This method creates a specialized HTTP client that handles:
   * - Automatic access token retrieval and injection
   * - DPoP (Demonstrating Proof-of-Possession) proof generation when enabled
   * - Token refresh and session management
   * - Error handling and retry logic for DPoP nonce errors
   * - Base URL resolution for relative requests
   *
   * The fetcher provides a high-level interface for making requests to protected resources
   * without manually handling authentication details.
   *
   * @template TOutput - Response type that extends the standard Response interface
   * @param req - Request object for session context (required for Pages Router, optional for App Router)
   * @param options - Configuration options for the fetcher
   * @param options.useDPoP - Enable DPoP for this fetcher instance (overrides global setting)
   * @param options.baseUrl - Base URL for resolving relative requests
   * @param options.getAccessToken - Custom access token factory function
   * @param options.fetch - Custom fetch implementation
   * @returns Promise that resolves to a configured Fetcher instance
   * @throws AccessTokenError when no active session exists
   *
   * @example
   * ```typescript
   * import { auth0 } from "@/lib/auth0";
   *
   * const fetcher = await auth0.createFetcher(undefined, {
   *   baseUrl: "https://api.example.com",
   *   useDPoP: true
   * });
   *
   * const response = await fetcher.fetchWithAuth("/users");
   * const users = await response.json();
   * ```
   *
   * @see {@link Fetcher} for details on using the returned fetcher instance
   * @see {@link FetcherMinimalConfig} for available configuration options
   */
  public async createFetcher<TOutput extends Response = Response>(
    req: PagesRouterRequest | NextRequest | Request | undefined,
    options: {
      /** Enable DPoP for this fetcher instance (overrides global setting) */
      useDPoP?: boolean;
      /** Custom access token factory function. If not provided, uses the default from hooks */
      getAccessToken?: AccessTokenFactory;
      /** Base URL for relative requests. Must be provided if using relative URLs */
      baseUrl?: string;
      /** Custom fetch implementation. Falls back to global fetch if not provided */
      fetch?: CustomFetchImpl<TOutput>;
    }
  ): Promise<Fetcher<TOutput>> {
    throw new Error("not implemented");
  }
}
