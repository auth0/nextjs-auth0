import type { IncomingMessage, ServerResponse } from "http";
import { cookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import { NextApiHandler, NextApiRequest, NextApiResponse } from "next/types.js";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  ConnectAccountError,
  ConnectAccountErrorCodes
} from "../errors/index.js";
import { DpopKeyPair, DpopOptions } from "../types/dpop.js";
import {
  AccessTokenForConnectionOptions,
  AuthorizationParameters,
  BackchannelAuthenticationOptions,
  ConnectAccountOptions,
  GetAccessTokenOptions,
  LogoutStrategy,
  SessionData,
  SessionDataStore,
  StartInteractiveLoginOptions,
  User
} from "../types/index.js";
import { DEFAULT_SCOPES } from "../utils/constants.js";
import { validateDpopConfiguration } from "../utils/dpopUtils.js";
import { isRequest } from "../utils/request.js";
import { getSessionChangesAfterGetAccessToken } from "../utils/session-changes-helpers.js";
import {
  AuthClient,
  BeforeSessionSavedHook,
  OnCallbackHook,
  Routes,
  RoutesOptions
} from "./auth-client.js";
import { RequestCookies, ResponseCookies } from "./cookies.js";
import { AccessTokenFactory, CustomFetchImpl, Fetcher } from "./fetcher.js";
import * as withApiAuthRequired from "./helpers/with-api-auth-required.js";
import {
  appRouteHandlerFactory,
  AppRouterPageRoute,
  pageRouteHandlerFactory,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouterOptions
} from "./helpers/with-page-auth-required.js";
import {
  AbstractSessionStore,
  SessionConfiguration,
  SessionCookieOptions
} from "./session/abstract-session-store.js";
import { StatefulSessionStore } from "./session/stateful-session-store.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TokenRequestCache } from "./token-request-cache.js";
import {
  TransactionCookieOptions,
  TransactionStore
} from "./transaction-store.js";

export interface Auth0ClientOptions {
  // authorization server configuration
  /**
   * The Auth0 domain for the tenant (e.g.: `example.us.auth0.com`).
   *
   * If it's not specified, it will be loaded from the `AUTH0_DOMAIN` environment variable.
   */
  domain?: string;
  /**
   * The Auth0 client ID.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_ID` environment variable.
   */
  clientId?: string;
  /**
   * The Auth0 client secret.
   *
   * If it's not specified, it will be loaded from the `AUTH0_CLIENT_SECRET` environment variable.
   */
  clientSecret?: string;
  /**
   * Additional parameters to send to the `/authorize` endpoint.
   */
  authorizationParameters?: AuthorizationParameters;
  /**
   * If enabled, the SDK will use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.
   */
  pushedAuthorizationRequests?: boolean;
  /**
   * Private key for use with `private_key_jwt` clients.
   * This should be a string that is the contents of a PEM file or a CryptoKey.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The algorithm used to sign the client assertion JWT.
   * Uses one of `token_endpoint_auth_signing_alg_values_supported` if not specified.
   * If the Authorization Server discovery document does not list `token_endpoint_auth_signing_alg_values_supported`
   * this property will be required.
   */
  clientAssertionSigningAlg?: string;

  // application configuration
  /**
   * The URL of your application (e.g.: `http://localhost:3000`).
   *
   * If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.
   */
  appBaseUrl?: string;
  /**
   * A 32-byte, hex-encoded secret used for encrypting cookies.
   *
   * If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.
   */
  secret?: string;
  /**
   * The path to redirect the user to after successfully authenticating. Defaults to `/`.
   */
  signInReturnToPath?: string;

  // session configuration
  /**
   * Configure the session timeouts and whether to use rolling sessions or not.
   *
   * See [Session configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for additional details.
   */
  session?: SessionConfiguration;

  // transaction cookie configuration
  /**
   * Configure the transaction cookie used to store the state of the authentication transaction.
   */
  transactionCookie?: TransactionCookieOptions;

  // logout configuration
  /**
   * Configure the logout strategy to use.
   *
   * - `'auto'` (default): Attempts OIDC RP-Initiated Logout first, falls back to `/v2/logout` if not supported
   * - `'oidc'`: Always uses OIDC RP-Initiated Logout (requires RP-Initiated Logout to be enabled)
   * - `'v2'`: Always uses the Auth0 `/v2/logout` endpoint (supports wildcards in allowed logout URLs)
   */
  logoutStrategy?: LogoutStrategy;

  /**
   * Configure whether to include id_token_hint in OIDC logout URLs.
   *
   * **Recommended (default)**: Set to `true` to include `id_token_hint` parameter.
   * Auth0 recommends using `id_token_hint` for secure logout as per the
   * OIDC specification.
   *
   * **Alternative approach**: Set to `false` if your application cannot securely
   * store ID tokens. When disabled, only `logout_hint` (session ID), `client_id`,
   * and `post_logout_redirect_uri` are sent.
   *
   *
   * @see https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#oidc-logout-endpoint-parameters
   * @default true (recommended and backwards compatible)
   */
  includeIdTokenHintInOIDCLogoutUrl?: boolean;

  // hooks
  /**
   * A method to manipulate the session before persisting it.
   *
   * See [beforeSessionSaved](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#beforesessionsaved) for additional details
   */
  beforeSessionSaved?: BeforeSessionSavedHook;
  /**
   * A method to handle errors or manage redirects after attempting to authenticate.
   *
   * See [onCallback](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oncallback) for additional details
   */
  onCallback?: OnCallbackHook;

  // provide a session store to persist sessions in your own data store
  /**
   * A custom session store implementation used to persist sessions to a data store.
   *
   * See [Database sessions](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#database-sessions) for additional details.
   */
  sessionStore?: SessionDataStore;

  /**
   * Configure the paths for the authentication routes.
   *
   * See [Custom routes](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#custom-routes) for additional details.
   */
  routes?: RoutesOptions;

  /**
   * Allow insecure requests to be made to the authorization server. This can be useful when testing
   * with a mock OIDC provider that does not support TLS, locally.
   * This option can only be used when NODE_ENV is not set to `production`.
   */
  allowInsecureRequests?: boolean;

  /**
   * Integer value for the HTTP timeout in milliseconds for authentication requests.
   * Defaults to `5000` ms.
   */
  httpTimeout?: number;

  /**
   * Boolean value to opt-out of sending the library name and version to your authorization server
   * via the `Auth0-Client` header. Defaults to `true`.
   */
  enableTelemetry?: boolean;

  /**
   * Boolean value to enable the `/auth/access-token` endpoint for use in the client app.
   *
   * Defaults to `true`.
   *
   * NOTE: Set this to `false` if your client does not need to directly interact with resource servers (Token Mediating Backend). This will be false for most apps.
   *
   * A security best practice is to disable this to avoid exposing access tokens to the client app.
   *
   * See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-token-mediating-backend
   */
  enableAccessTokenEndpoint?: boolean;

  /**
   * If true, the profile endpoint will return a 204 No Content response when the user is not authenticated
   * instead of returning a 401 Unauthorized response.
   *
   * Defaults to `false`.
   */
  noContentProfileResponseWhenUnauthenticated?: boolean;

  enableParallelTransactions?: boolean;

  /**
   * If true, the `/auth/connect` endpoint will be mounted to enable users to connect additional accounts.
   */
  enableConnectAccountEndpoint?: boolean;

  // DPoP Configuration
  /**
   * Enable DPoP (Demonstrating Proof-of-Possession) for enhanced OAuth 2.0 security.
   *
   * When enabled, the SDK will:
   * - Generate DPoP proofs for token requests and protected resource requests
   * - Bind access tokens cryptographically to the client's key pair
   * - Prevent token theft and replay attacks
   * - Handle DPoP nonce errors with automatic retry logic
   *
   * DPoP requires an ES256 key pair that can be provided via `dpopKeyPair` option
   * or loaded from environment variables `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY`.
   *
   * @default false
   *
   * @example Enable DPoP with generated keys
   * ```typescript
   * import { generateKeyPair } from "oauth4webapi";
   *
   * const dpopKeyPair = await generateKeyPair("ES256");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair
   * });
   * ```
   *
   * @example Enable DPoP with environment variables
   * ```typescript
   * // .env.local
   * // AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
   * // AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true
   *   // Keys loaded automatically from environment
   * });
   * ```
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
   */
  useDPoP?: boolean;

  /**
   * ES256 key pair for DPoP proof generation.
   *
   * If not provided when `useDPoP` is true, the SDK will attempt to load keys from
   * environment variables `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY`.
   * Keys must be in PEM format and use the P-256 elliptic curve.
   *
   * @example Provide key pair directly
   * ```typescript
   * import { generateKeyPair } from "oauth4webapi";
   *
   * const keyPair = await generateKeyPair("ES256");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair: keyPair
   * });
   * ```
   *
   * @example Load from files
   * ```typescript
   * import { importSPKI, importPKCS8 } from "jose";
   * import { readFileSync } from "fs";
   *
   * const publicKeyPem = readFileSync("dpop-public.pem", "utf8");
   * const privateKeyPem = readFileSync("dpop-private.pem", "utf8");
   *
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopKeyPair: {
   *     publicKey: await importSPKI(publicKeyPem, "ES256"),
   *     privateKey: await importPKCS8(privateKeyPem, "ES256")
   *   }
   * });
   * ```
   *
   * @see {@link DpopKeyPair} for the key pair interface
   * @see {@link generateDpopKeyPair} for generating new key pairs
   */
  dpopKeyPair?: DpopKeyPair;

  /**
   * Configuration options for DPoP timing validation and retry behavior.
   *
   * These options control how the SDK validates DPoP proof timing and handles
   * nonce errors. Proper configuration is important for both security and reliability.
   *
   * @example Basic configuration
   * ```typescript
   * const auth0 = new Auth0Client({
   *   useDPoP: true,
   *   dpopOptions: {
   *     clockTolerance: 60,    // Allow 60 seconds clock difference
   *     clockSkew: 0,          // No clock adjustment needed
   *     retry: {
   *       delay: 200,          // 200ms delay before retry
   *       jitter: true         // Add randomness to prevent thundering herd
   *     }
   *   }
   * });
   * ```
   *
   * @example Environment variable configuration
   * ```bash
   * # .env.local
   * AUTH0_DPOP_CLOCK_SKEW=0
   * AUTH0_DPOP_CLOCK_TOLERANCE=30
   * AUTH0_RETRY_DELAY=100
   * AUTH0_RETRY_JITTER=true
   * ```
   *
   * @see {@link DpopOptions} for detailed option descriptions
   */
  dpopOptions?: DpopOptions;
}

export type PagesRouterRequest = IncomingMessage | NextApiRequest;
export type PagesRouterResponse =
  | ServerResponse<IncomingMessage>
  | NextApiResponse;

export class Auth0Client {
  private transactionStore: TransactionStore;
  private sessionStore: AbstractSessionStore;
  private authClient: AuthClient;
  private routes: Routes;
  private domain: string;
  #options: Auth0ClientOptions;

  // Cache for in-flight token requests to prevent race conditions
  #tokenRequestCache = new TokenRequestCache();

  constructor(options: Auth0ClientOptions = {}) {
    this.#options = options;
    // Extract and validate required options
    const {
      domain,
      clientId,
      clientSecret,
      appBaseUrl,
      secret,
      clientAssertionSigningKey
    } = this.validateAndExtractRequiredOptions(options);
    this.domain = domain;

    const clientAssertionSigningAlg =
      options.clientAssertionSigningAlg ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG;

    // Validate DPoP configuration and resolve from environment variables if needed
    const {
      dpopKeyPair: resolvedDpopKeyPair,
      dpopOptions: resolvedDpopOptions
    } = validateDpopConfiguration(options);

    // Auto-detect base path for cookie configuration
    const basePath = process.env.NEXT_PUBLIC_BASE_PATH;

    const sessionCookieOptions: SessionCookieOptions = {
      name: options.session?.cookie?.name ?? "__session",
      secure:
        options.session?.cookie?.secure ??
        process.env.AUTH0_COOKIE_SECURE === "true",
      sameSite:
        options.session?.cookie?.sameSite ??
        (process.env.AUTH0_COOKIE_SAME_SITE as "lax" | "strict" | "none") ??
        "lax",
      path:
        options.session?.cookie?.path ??
        process.env.AUTH0_COOKIE_PATH ??
        basePath ??
        "/",
      transient:
        options.session?.cookie?.transient ??
        process.env.AUTH0_COOKIE_TRANSIENT === "true",
      domain: options.session?.cookie?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    };

    const transactionCookieOptions: TransactionCookieOptions = {
      prefix: options.transactionCookie?.prefix ?? "__txn_",
      secure: options.transactionCookie?.secure ?? false,
      sameSite: options.transactionCookie?.sameSite ?? "lax",
      path: options.transactionCookie?.path ?? basePath ?? "/",
      maxAge: options.transactionCookie?.maxAge ?? 3600
    };

    if (appBaseUrl) {
      const { protocol } = new URL(appBaseUrl);
      if (protocol === "https:") {
        sessionCookieOptions.secure = true;
        transactionCookieOptions.secure = true;
      }
    }

    this.routes = {
      login: process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login",
      logout: "/auth/logout",
      callback: "/auth/callback",
      backChannelLogout: "/auth/backchannel-logout",
      profile: process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
      accessToken:
        process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
      connectAccount: "/auth/connect",
      ...options.routes
    };

    this.transactionStore = new TransactionStore({
      secret,
      cookieOptions: transactionCookieOptions,
      enableParallelTransactions: options.enableParallelTransactions ?? true
    });

    this.sessionStore = options.sessionStore
      ? new StatefulSessionStore({
          ...options.session,
          secret,
          store: options.sessionStore,
          cookieOptions: sessionCookieOptions
        })
      : new StatelessSessionStore({
          ...options.session,
          secret,
          cookieOptions: sessionCookieOptions
        });

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
      logoutStrategy: options.logoutStrategy,
      includeIdTokenHintInOIDCLogoutUrl:
        options.includeIdTokenHintInOIDCLogoutUrl,

      beforeSessionSaved: options.beforeSessionSaved,
      onCallback: options.onCallback,

      routes: this.routes,

      allowInsecureRequests: options.allowInsecureRequests,
      httpTimeout: options.httpTimeout,
      enableTelemetry: options.enableTelemetry,
      enableAccessTokenEndpoint: options.enableAccessTokenEndpoint,
      noContentProfileResponseWhenUnauthenticated:
        options.noContentProfileResponseWhenUnauthenticated,
      enableConnectAccountEndpoint: options.enableConnectAccountEndpoint,
      useDPoP: options.useDPoP || false,
      dpopKeyPair: options.dpopKeyPair || resolvedDpopKeyPair,
      dpopOptions: options.dpopOptions || resolvedDpopOptions
    });
  }

  /**
   * middleware mounts the SDK routes to run as a middleware function.
   */
  middleware(req: NextRequest): Promise<NextResponse> {
    return this.authClient.handler.bind(this.authClient)(req);
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
    req?: PagesRouterRequest | NextRequest
  ): Promise<SessionData | null> {
    if (req) {
      // middleware usage
      if (req instanceof NextRequest) {
        return this.sessionStore.get(req.cookies);
      }

      // pages router usage
      return this.sessionStore.get(this.createRequestCookies(req));
    }

    // app router usage: Server Components, Server Actions, Route Handlers
    return this.sessionStore.get(await cookies());
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
  async getAccessToken(
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
   * {@link https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token|See Auth0 Documentation on Multi-resource Refresh Tokens}
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
    const defaultOptions: GetAccessTokenOptions = {
      refresh: false
    };

    let req: PagesRouterRequest | NextRequest | undefined = undefined;
    let res: PagesRouterResponse | NextResponse | undefined = undefined;
    let options: GetAccessTokenOptions = {};

    // Determine which overload was called based on arguments
    if (
      arg1 &&
      (arg1 instanceof Request || typeof (arg1 as any).headers === "object")
    ) {
      // Case: getAccessToken(req, res, options?)
      req = arg1 as PagesRouterRequest | NextRequest;
      res = arg2; // arg2 must be Response if arg1 is Request
      // Merge provided options (arg3) with defaults
      options = { ...defaultOptions, ...(arg3 ?? {}) };
      if (!res) {
        throw new TypeError(
          "getAccessToken(req, res): The 'res' argument is missing. Both 'req' and 'res' must be provided together for Pages Router or middleware usage."
        );
      }
    } else {
      // Case: getAccessToken(options?) or getAccessToken()
      // arg1 (if present) must be options, arg2 and arg3 must be undefined.
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "getAccessToken: Invalid arguments. Valid signatures are getAccessToken(), getAccessToken(options), or getAccessToken(req, res, options)."
        );
      }
      // Merge provided options (arg1) with defaults
      options = {
        ...defaultOptions,
        ...((arg1 as GetAccessTokenOptions) ?? {})
      };
    }

    // Execute the token request with caching to avoid duplicate in-flight requests
    return this.#tokenRequestCache.execute(
      () => this.executeGetAccessToken(req, res, options),
      {
        options,
        authorizationParameters: this.#options.authorizationParameters
      }
    );
  }

  /**
   * Core implementation of getAccessToken that performs the actual token retrieval.
   * This is separated to enable request coalescing via the cache.
   */
  private async executeGetAccessToken(
    req: PagesRouterRequest | NextRequest | undefined,
    res: PagesRouterResponse | NextResponse | undefined,
    options: GetAccessTokenOptions
  ): Promise<{
    token: string;
    expiresAt: number;
    scope?: string;
    token_type?: string;
    audience?: string;
  }> {
    const session: SessionData | null = req
      ? await this.getSession(req)
      : await this.getSession();

    if (!session) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    const [error, getTokenSetResponse] = await this.authClient.getTokenSet(
      session,
      options
    );
    if (error) {
      throw error;
    }
    const { tokenSet, idTokenClaims } = getTokenSetResponse;
    // update the session with the new token set, if necessary
    const sessionChanges = getSessionChangesAfterGetAccessToken(
      session,
      tokenSet,
      {
        scope: this.#options.authorizationParameters?.scope ?? DEFAULT_SCOPES,
        audience: this.#options.authorizationParameters?.audience
      }
    );

    if (sessionChanges) {
      if (idTokenClaims) {
        session.user = idTokenClaims as User;
      }
      // call beforeSessionSaved callback if present
      // if not then filter id_token claims with default rules
      const finalSession = await this.authClient.finalizeSession(
        session,
        tokenSet.idToken
      );
      await this.saveToSession(
        {
          ...finalSession,
          ...sessionChanges
        },
        req,
        res
      );
    }

    return {
      token: tokenSet.accessToken,
      scope: tokenSet.scope,
      expiresAt: tokenSet.expiresAt,
      token_type: tokenSet.token_type,
      audience: tokenSet.audience
    };
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
    req: PagesRouterRequest | NextRequest | undefined,
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
    req?: PagesRouterRequest | NextRequest,
    res?: PagesRouterResponse | NextResponse
  ): Promise<{ token: string; expiresAt: number; scope?: string }> {
    const session: SessionData | null = req
      ? await this.getSession(req)
      : await this.getSession();

    if (!session) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    // Find the connection token set in the session
    const existingTokenSet = session.connectionTokenSets?.find(
      (tokenSet) => tokenSet.connection === options.connection
    );

    const [error, retrievedTokenSet] =
      await this.authClient.getConnectionTokenSet(
        session.tokenSet,
        existingTokenSet,
        options
      );

    if (error !== null) {
      throw error;
    }

    // If we didn't have a corresponding connection token set in the session
    // or if the one we have in the session does not match the one we received
    // We want to update the store incase we retrieved a token set.
    if (
      retrievedTokenSet &&
      (!existingTokenSet ||
        retrievedTokenSet.accessToken !== existingTokenSet.accessToken ||
        retrievedTokenSet.expiresAt !== existingTokenSet.expiresAt ||
        retrievedTokenSet.scope !== existingTokenSet.scope)
    ) {
      let tokenSets;

      // If we already had the connection token set in the session
      // we need to update the item in the array
      // If not, we need to add it.
      if (existingTokenSet) {
        tokenSets = session.connectionTokenSets?.map((tokenSet) =>
          tokenSet.connection === options.connection
            ? retrievedTokenSet
            : tokenSet
        );
      } else {
        tokenSets = [...(session.connectionTokenSets || []), retrievedTokenSet];
      }

      await this.saveToSession(
        {
          ...session,
          connectionTokenSets: tokenSets
        },
        req,
        res
      );
    }

    return {
      token: retrievedTokenSet.accessToken,
      scope: retrievedTokenSet.scope,
      expiresAt: retrievedTokenSet.expiresAt
    };
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
    reqOrSession: PagesRouterRequest | NextRequest | SessionData,
    res?: PagesRouterResponse | NextResponse,
    sessionData?: SessionData
  ) {
    if (!res) {
      // app router: Server Actions, Route Handlers
      const existingSession = await this.getSession();

      if (!existingSession) {
        throw new Error("The user is not authenticated.");
      }

      const updatedSession = reqOrSession as SessionData;
      if (!updatedSession) {
        throw new Error("The session data is missing.");
      }

      await this.sessionStore.set(await cookies(), await cookies(), {
        ...updatedSession,
        internal: {
          ...existingSession.internal
        }
      });
    } else {
      const req = reqOrSession as PagesRouterRequest | NextRequest;

      if (!sessionData) {
        throw new Error("The session data is missing.");
      }

      if (req instanceof NextRequest && res instanceof NextResponse) {
        // middleware usage
        const existingSession = await this.getSession(req);

        if (!existingSession) {
          throw new Error("The user is not authenticated.");
        }

        await this.sessionStore.set(req.cookies, res.cookies, {
          ...sessionData,
          internal: {
            ...existingSession.internal
          }
        });
      } else {
        // pages router usage
        const existingSession = await this.getSession(
          req as PagesRouterRequest
        );

        if (!existingSession) {
          throw new Error("The user is not authenticated.");
        }

        const resHeaders = new Headers();
        const resCookies = new ResponseCookies(resHeaders);
        const updatedSession = sessionData as SessionData;
        const reqCookies = this.createRequestCookies(req as PagesRouterRequest);
        const pagesRouterRes = res as PagesRouterResponse;

        await this.sessionStore.set(reqCookies, resCookies, {
          ...updatedSession,
          internal: {
            ...existingSession.internal
          }
        });

        for (const [key, value] of resHeaders.entries()) {
          pagesRouterRes.setHeader(key, value);
        }
      }
    }
  }

  private createRequestCookies(req: PagesRouterRequest) {
    const headers = new Headers();

    for (const key in req.headers) {
      if (Array.isArray(req.headers[key])) {
        for (const value of req.headers[key]) {
          headers.append(key, value);
        }
      } else {
        headers.append(key, req.headers[key] ?? "");
      }
    }

    return new RequestCookies(headers);
  }

  async startInteractiveLogin(
    options: StartInteractiveLoginOptions = {}
  ): Promise<NextResponse> {
    return this.authClient.startInteractiveLogin(options);
  }

  /**
   * Authenticates using Client-Initiated Backchannel Authentication and returns the token set and optionally the ID token claims and authorization details.
   *
   * This method will initialize the backchannel authentication process with Auth0, and poll the token endpoint until the authentication is complete.
   *
   * Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
   * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
   */
  async getTokenByBackchannelAuth(options: BackchannelAuthenticationOptions) {
    const [error, response] =
      await this.authClient.backchannelAuthentication(options);

    if (error) {
      throw error;
    }

    return response;
  }

  /**
   * Initiates the Connect Account flow to connect a third-party account to the user's profile.
   * If the user does not have an active session, a `ConnectAccountError` is thrown.
   *
   * This method first attempts to obtain an access token with the `create:me:connected_accounts` scope
   * for the My Account API to create a connected account for the user.
   *
   * The user will then be redirected to authorize the connection with the third-party provider.
   */
  async connectAccount(options: ConnectAccountOptions): Promise<NextResponse> {
    const session = await this.getSession();

    if (!session) {
      throw new ConnectAccountError({
        code: ConnectAccountErrorCodes.MISSING_SESSION,
        message: "The user does not have an active session."
      });
    }

    const getMyAccountTokenOpts = {
      audience: `${this.issuer}/me/`,
      scope: "create:me:connected_accounts"
    };

    const accessToken = await this.getAccessToken(getMyAccountTokenOpts);

    const [error, connectAccountResponse] =
      await this.authClient.connectAccount({
        ...options,
        tokenSet: {
          accessToken: accessToken.token,
          expiresAt: accessToken.expiresAt,
          scope: getMyAccountTokenOpts.scope,
          audience: accessToken.audience
        }
      });

    if (error) {
      throw error;
    }

    return connectAccountResponse;
  }

  withPageAuthRequired(
    fnOrOpts?: WithPageAuthRequiredPageRouterOptions | AppRouterPageRoute,
    opts?: WithPageAuthRequiredAppRouterOptions
  ) {
    const config = {
      loginUrl: this.routes.login
    };
    const appRouteHandler = appRouteHandlerFactory(this, config);
    const pageRouteHandler = pageRouteHandlerFactory(this, config);

    if (typeof fnOrOpts === "function") {
      return appRouteHandler(fnOrOpts, opts);
    }

    return pageRouteHandler(fnOrOpts);
  }

  withApiAuthRequired(
    apiRoute: withApiAuthRequired.AppRouteHandlerFn | NextApiHandler
  ) {
    const pageRouteHandler = withApiAuthRequired.pageRouteHandlerFactory(this);
    const appRouteHandler = withApiAuthRequired.appRouteHandlerFactory(this);

    return (
      req: NextRequest | NextApiRequest,
      resOrParams:
        | withApiAuthRequired.AppRouteHandlerFnContext
        | NextApiResponse
    ) => {
      if (isRequest(req)) {
        return appRouteHandler(
          apiRoute as withApiAuthRequired.AppRouteHandlerFn
        )(
          req as NextRequest,
          resOrParams as withApiAuthRequired.AppRouteHandlerFnContext
        );
      }

      return (
        pageRouteHandler as withApiAuthRequired.WithApiAuthRequiredPageRoute
      )(apiRoute as NextApiHandler)(
        req as NextApiRequest,
        resOrParams as NextApiResponse
      );
    };
  }

  private async saveToSession(
    data: SessionData,
    req?: PagesRouterRequest | NextRequest,
    res?: PagesRouterResponse | NextResponse
  ) {
    if (req && res) {
      if (req instanceof NextRequest && res instanceof NextResponse) {
        // middleware usage
        await this.sessionStore.set(req.cookies, res.cookies, data);
      } else {
        // pages router usage
        const resHeaders = new Headers();
        const resCookies = new ResponseCookies(resHeaders);
        const pagesRouterRes = res as PagesRouterResponse;

        await this.sessionStore.set(
          this.createRequestCookies(req as PagesRouterRequest),
          resCookies,
          data
        );

        for (const [key, value] of resHeaders.entries()) {
          pagesRouterRes.setHeader(key, value);
        }
      }
    } else {
      // app router usage: Server Components, Server Actions, Route Handlers
      try {
        await this.sessionStore.set(await cookies(), await cookies(), data);
      } catch (e) {
        if (process.env.NODE_ENV === "development") {
          console.warn(
            "Failed to persist the updated token set. `getAccessToken()` was likely called from a Server Component which cannot set cookies."
          );
        }
      }
    }
  }

  /**
   * Validates and extracts required configuration options.
   * @param options The client options
   * @returns The validated required options
   * @throws ConfigurationError if any required option is missing
   */
  private validateAndExtractRequiredOptions(options: Auth0ClientOptions) {
    // Base required options that are always needed
    const requiredOptions = {
      domain: options.domain ?? process.env.AUTH0_DOMAIN,
      clientId: options.clientId ?? process.env.AUTH0_CLIENT_ID,
      appBaseUrl: options.appBaseUrl ?? process.env.APP_BASE_URL,
      secret: options.secret ?? process.env.AUTH0_SECRET
    };

    // Check client authentication options - either clientSecret OR clientAssertionSigningKey must be provided
    const clientSecret =
      options.clientSecret ?? process.env.AUTH0_CLIENT_SECRET;
    const clientAssertionSigningKey =
      options.clientAssertionSigningKey ??
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY;
    const hasClientAuthentication = !!(
      clientSecret || clientAssertionSigningKey
    );

    const missing = Object.entries(requiredOptions)
      .filter(([, value]) => !value)
      .map(([key]) => key);

    // Add client authentication error if neither option is provided
    if (!hasClientAuthentication) {
      missing.push("clientAuthentication");
    }

    if (missing.length) {
      // Map of option keys to their exact environment variable names
      const envVarNames: Record<string, string> = {
        domain: "AUTH0_DOMAIN",
        clientId: "AUTH0_CLIENT_ID",
        appBaseUrl: "APP_BASE_URL",
        secret: "AUTH0_SECRET"
      };

      // Standard intro message explaining the issue
      let errorMessage =
        "WARNING: Not all required options were provided when creating an instance of Auth0Client. Ensure to provide all missing options, either by passing it to the Auth0Client constructor, or by setting the corresponding environment variable.\n";

      // Add specific details for each missing option
      missing.forEach((key) => {
        if (key === "clientAuthentication") {
          errorMessage += `Missing: clientAuthentication: Set either AUTH0_CLIENT_SECRET env var or AUTH0_CLIENT_ASSERTION_SIGNING_KEY env var, or pass clientSecret or clientAssertionSigningKey in options\n`;
        } else if (envVarNames[key]) {
          errorMessage += `Missing: ${key}: Set ${envVarNames[key]} env var or pass ${key} in options\n`;
        } else {
          errorMessage += `Missing: ${key}\n`;
        }
      });

      console.error(errorMessage.trim());
    }

    // Prepare the result object with all validated options
    const result = {
      ...requiredOptions,
      clientSecret,
      clientAssertionSigningKey
    };

    // Type-safe assignment after validation
    return result as {
      [K in keyof typeof result]: NonNullable<(typeof result)[K]>;
    };
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
    req: PagesRouterRequest | NextRequest | undefined,
    options: {
      /** Enable DPoP for this fetcher instance (overrides global setting) */
      useDPoP?: boolean;
      /** Custom access token factory function. If not provided, uses the default from hooks */
      getAccessToken?: AccessTokenFactory;
      /** Base URL for relative requests. Must be provided if using relative URLs */
      baseUrl?: string;
      /** Custom fetch implementation. Falls back to global fetch if not provided */
      fetch?: CustomFetchImpl<TOutput>;
      /**
       * @future This parameter is reserved for future implementation.
       */
      nonceStorageId?: string;
    }
  ) {
    const session: SessionData | null = req
      ? await this.getSession(req)
      : await this.getSession();

    if (!session) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    const getAccessToken = async (
      getAccessTokenOptions: GetAccessTokenOptions
    ) => {
      const [error, getTokenSetResponse] = await this.authClient.getTokenSet(
        session,
        getAccessTokenOptions || {}
      );
      if (error) {
        throw error;
      }
      return getTokenSetResponse.tokenSet;
    };

    const fetcher: Fetcher<TOutput> = await this.authClient.fetcherFactory({
      ...options,
      getAccessToken
    });

    return fetcher;
  }

  private get issuer(): string {
    return this.domain.startsWith("http://") ||
      this.domain.startsWith("https://")
      ? this.domain
      : `https://${this.domain}`;
  }
}
