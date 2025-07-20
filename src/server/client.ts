import type { IncomingMessage, ServerResponse } from "node:http";
import { cookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import { NextApiHandler, NextApiRequest, NextApiResponse } from "next/types.js";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode
} from "../errors/index.js";
import {
  AccessTokenForConnectionOptions,
  AuthorizationParameters,
  LogoutStrategy,
  SessionData,
  SessionDataStore,
  StartInteractiveLoginOptions,
  User
} from "../types/index.js";
import { isRequest } from "../utils/request.js";
import {
  AuthClient,
  BeforeSessionSavedHook,
  OnCallbackHook,
  Routes,
  RoutesOptions
} from "./auth-client.js";
import { RequestCookies, ResponseCookies } from "./cookies.js";
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

  constructor(options: Auth0ClientOptions = {}) {
    // Extract and validate required options
    const {
      domain,
      clientId,
      clientSecret,
      appBaseUrl,
      secret,
      clientAssertionSigningKey
    } = this.validateAndExtractRequiredOptions(options);

    const clientAssertionSigningAlg =
      options.clientAssertionSigningAlg ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG;

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
        options.session?.cookie?.path ?? process.env.AUTH0_COOKIE_PATH ?? "/",
      transient:
        options.session?.cookie?.transient ??
        process.env.AUTH0_COOKIE_TRANSIENT === "true",
      domain: options.session?.cookie?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    };

    const transactionCookieOptions: TransactionCookieOptions = {
      prefix: options.transactionCookie?.prefix ?? "__txn_",
      secure: options.transactionCookie?.secure ?? false,
      sameSite: options.transactionCookie?.sameSite ?? "lax",
      path: options.transactionCookie?.path ?? "/"
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
      ...options.routes
    };

    this.transactionStore = new TransactionStore({
      ...options.session,
      secret,
      cookieOptions: transactionCookieOptions
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

      beforeSessionSaved: options.beforeSessionSaved,
      onCallback: options.onCallback,

      routes: this.routes,

      allowInsecureRequests: options.allowInsecureRequests,
      httpTimeout: options.httpTimeout,
      enableTelemetry: options.enableTelemetry,
      enableAccessTokenEndpoint: options.enableAccessTokenEndpoint,
      noContentProfileResponseWhenUnauthenticated:
        options.noContentProfileResponseWhenUnauthenticated
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
  ): Promise<{ token: string; expiresAt: number; scope?: string }>;

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
  ): Promise<{ token: string; expiresAt: number; scope?: string }>;

  /**
   * getAccessToken returns the access token.
   *
   * NOTE: Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
   * It is recommended to call `getAccessToken(req, res)` in the middleware if you need to retrieve the access token in a Server Component to ensure the updated token set is persisted.
   */
  async getAccessToken(
    arg1?: PagesRouterRequest | NextRequest | GetAccessTokenOptions,
    arg2?: PagesRouterResponse | NextResponse,
    arg3?: GetAccessTokenOptions
  ): Promise<{ token: string; expiresAt: number; scope?: string }> {
    const defaultOptions: Required<GetAccessTokenOptions> = {
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
      session.tokenSet,
      options.refresh
    );
    if (error) {
      throw error;
    }
    const { tokenSet, idTokenClaims } = getTokenSetResponse;
    // update the session with the new token set, if necessary
    if (
      tokenSet.accessToken !== session.tokenSet.accessToken ||
      tokenSet.expiresAt !== session.tokenSet.expiresAt ||
      tokenSet.refreshToken !== session.tokenSet.refreshToken
    ) {
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
          tokenSet
        },
        req,
        res
      );
    }

    return {
      token: tokenSet.accessToken,
      scope: tokenSet.scope,
      expiresAt: tokenSet.expiresAt
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

    // If we didnt have a corresponding connection token set in the session
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
    options: StartInteractiveLoginOptions
  ): Promise<NextResponse> {
    return this.authClient.startInteractiveLogin(options);
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
}

export type GetAccessTokenOptions = {
  refresh?: boolean;
};
