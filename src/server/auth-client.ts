import { NextResponse, type NextRequest } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";

import packageJson from "../../package.json" with { type: "json" };
import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  AuthorizationCodeGrantError,
  AuthorizationCodeGrantRequestError,
  AuthorizationError,
  BackchannelLogoutError,
  DiscoveryError,
  InvalidStateError,
  MissingStateError,
  OAuth2Error,
  SdkError
} from "../errors/index.js";
import {
  AccessTokenForConnectionOptions,
  AuthorizationParameters,
  ConnectionTokenSet,
  LogoutStrategy,
  LogoutToken,
  SessionData,
  StartInteractiveLoginOptions,
  TokenSet,
  User
} from "../types/index.js";
import {
  ensureNoLeadingSlash,
  ensureTrailingSlash,
  normalizeWithBasePath,
  removeTrailingSlash
} from "../utils/pathUtils.js";
import { toSafeRedirect } from "../utils/url-helpers.js";
import { addCacheControlHeadersForSession } from "./cookies.js";
import { AbstractSessionStore } from "./session/abstract-session-store.js";
import { TransactionState, TransactionStore } from "./transaction-store.js";
import { filterDefaultIdTokenClaims } from "./user.js";

export type BeforeSessionSavedHook = (
  session: SessionData,
  idToken: string | null
) => Promise<SessionData>;

export type OnCallbackContext = {
  returnTo?: string;
};
export type OnCallbackHook = (
  error: SdkError | null,
  ctx: OnCallbackContext,
  session: SessionData | null
) => Promise<NextResponse>;

// params passed to the /authorize endpoint that cannot be overwritten
const INTERNAL_AUTHORIZE_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce"
];

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"].join(
  " "
);

/**
 * A constant representing the grant type for federated connection access token exchange.
 *
 * This grant type is used in OAuth token exchange scenarios where a federated connection
 * access token is required. It is specific to Auth0's implementation and follows the
 * "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" format.
 */
const GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token";

/**
 * Constant representing the subject type for a refresh token.
 * This is used in OAuth 2.0 token exchange to specify that the token being exchanged is a refresh token.
 *
 * @see {@link https://tools.ietf.org/html/rfc8693#section-3.1 RFC 8693 Section 3.1}
 */
const SUBJECT_TYPE_REFRESH_TOKEN =
  "urn:ietf:params:oauth:token-type:refresh_token";

/**
 * A constant representing the token type for federated connection access tokens.
 * This is used to specify the type of token being requested from Auth0.
 *
 * @constant
 * @type {string}
 */
const REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN =
  "http://auth0.com/oauth/token-type/federated-connection-access-token";

export interface Routes {
  login: string;
  logout: string;
  callback: string;
  profile: string;
  accessToken: string;
  backChannelLogout: string;
}
export type RoutesOptions = Partial<
  Pick<Routes, "login" | "callback" | "logout" | "backChannelLogout">
>;

export interface AuthClientOptions {
  transactionStore: TransactionStore;
  sessionStore: AbstractSessionStore;

  domain: string;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | jose.CryptoKey;
  clientAssertionSigningAlg?: string;
  authorizationParameters?: AuthorizationParameters;
  pushedAuthorizationRequests?: boolean;

  secret: string;
  appBaseUrl: string;
  signInReturnToPath?: string;
  logoutStrategy?: LogoutStrategy;

  beforeSessionSaved?: BeforeSessionSavedHook;
  onCallback?: OnCallbackHook;

  routes: Routes;

  // custom fetch implementation to allow for dependency injection
  fetch?: typeof fetch;
  jwksCache?: jose.JWKSCacheInput;
  allowInsecureRequests?: boolean;
  httpTimeout?: number;
  enableTelemetry?: boolean;
  enableAccessTokenEndpoint?: boolean;
  noContentProfileResponseWhenUnauthenticated?: boolean;
}

function createRouteUrl(path: string, baseUrl: string) {
  return new URL(
    ensureNoLeadingSlash(normalizeWithBasePath(path)),
    ensureTrailingSlash(baseUrl)
  );
}

export class AuthClient {
  private transactionStore: TransactionStore;
  private sessionStore: AbstractSessionStore;

  private clientMetadata: oauth.Client;
  private clientSecret?: string;
  private clientAssertionSigningKey?: string | jose.CryptoKey;
  private clientAssertionSigningAlg: string;
  private domain: string;
  private authorizationParameters: AuthorizationParameters;
  private pushedAuthorizationRequests: boolean;

  private appBaseUrl: string;
  private signInReturnToPath: string;
  private logoutStrategy: LogoutStrategy;

  private beforeSessionSaved?: BeforeSessionSavedHook;
  private onCallback: OnCallbackHook;

  private routes: Routes;

  private fetch: typeof fetch;
  private jwksCache: jose.JWKSCacheInput;
  private allowInsecureRequests: boolean;
  private httpOptions: () => oauth.HttpRequestOptions<"GET" | "POST">;

  private authorizationServerMetadata?: oauth.AuthorizationServer;

  private readonly enableAccessTokenEndpoint: boolean;
  private readonly noContentProfileResponseWhenUnauthenticated: boolean;

  constructor(options: AuthClientOptions) {
    // dependencies
    this.fetch = options.fetch || fetch;
    this.jwksCache = options.jwksCache || {};
    this.allowInsecureRequests = options.allowInsecureRequests ?? false;
    this.httpOptions = () => {
      const headers = new Headers();
      const enableTelemetry = options.enableTelemetry ?? true;
      const timeout = options.httpTimeout ?? 5000;
      if (enableTelemetry) {
        const name = "nextjs-auth0";
        const version = packageJson.version;

        headers.set("User-Agent", `${name}/${version}`);
        headers.set(
          "Auth0-Client",
          encodeBase64(
            JSON.stringify({
              name,
              version
            })
          )
        );
      }

      return {
        signal: AbortSignal.timeout(timeout),
        headers
      };
    };

    if (this.allowInsecureRequests && process.env.NODE_ENV === "production") {
      console.warn(
        "allowInsecureRequests is enabled in a production environment. This is not recommended."
      );
    }

    // stores
    this.transactionStore = options.transactionStore;
    this.sessionStore = options.sessionStore;

    // authorization server
    this.domain = options.domain;
    this.clientMetadata = { client_id: options.clientId };
    this.clientSecret = options.clientSecret;
    this.authorizationParameters = options.authorizationParameters || {
      scope: DEFAULT_SCOPES
    };
    this.pushedAuthorizationRequests =
      options.pushedAuthorizationRequests ?? false;
    this.clientAssertionSigningKey = options.clientAssertionSigningKey;
    this.clientAssertionSigningAlg =
      options.clientAssertionSigningAlg || "RS256";

    if (!this.authorizationParameters.scope) {
      this.authorizationParameters.scope = DEFAULT_SCOPES;
    }

    const scope = this.authorizationParameters.scope
      .split(" ")
      .map((s) => s.trim());
    if (!scope.includes("openid")) {
      throw new Error(
        "The 'openid' scope must be included in the set of scopes. See https://auth0.com/docs"
      );
    }

    // application
    this.appBaseUrl = options.appBaseUrl;
    this.signInReturnToPath = options.signInReturnToPath || "/";

    // validate logout strategy
    const validStrategies = ["auto", "oidc", "v2"] as const;
    let logoutStrategy = options.logoutStrategy || "auto";
    if (!validStrategies.includes(logoutStrategy)) {
      console.error(
        `Invalid logoutStrategy: ${logoutStrategy}. Must be one of: ${validStrategies.join(", ")}. Defaulting to "auto"`
      );
      logoutStrategy = "auto";
    }
    this.logoutStrategy = logoutStrategy;

    // hooks
    this.beforeSessionSaved = options.beforeSessionSaved;
    this.onCallback = options.onCallback || this.defaultOnCallback;

    // routes
    this.routes = options.routes;

    this.enableAccessTokenEndpoint = options.enableAccessTokenEndpoint ?? true;
    this.noContentProfileResponseWhenUnauthenticated =
      options.noContentProfileResponseWhenUnauthenticated ?? false;
  }

  async handler(req: NextRequest): Promise<NextResponse> {
    const { pathname } = req.nextUrl;
    const sanitizedPathname = removeTrailingSlash(pathname);
    const method = req.method;

    if (method === "GET" && sanitizedPathname === this.routes.login) {
      return this.handleLogin(req);
    } else if (method === "GET" && sanitizedPathname === this.routes.logout) {
      return this.handleLogout(req);
    } else if (method === "GET" && sanitizedPathname === this.routes.callback) {
      return this.handleCallback(req);
    } else if (method === "GET" && sanitizedPathname === this.routes.profile) {
      return this.handleProfile(req);
    } else if (
      method === "GET" &&
      sanitizedPathname === this.routes.accessToken &&
      this.enableAccessTokenEndpoint
    ) {
      return this.handleAccessToken(req);
    } else if (
      method === "POST" &&
      sanitizedPathname === this.routes.backChannelLogout
    ) {
      return this.handleBackChannelLogout(req);
    } else {
      // no auth handler found, simply touch the sessions
      // TODO: this should only happen if rolling sessions are enabled. Also, we should
      // try to avoid reading from the DB (for stateful sessions) on every request if possible.
      const res = NextResponse.next();
      const session = await this.sessionStore.get(req.cookies);

      if (session) {
        // we pass the existing session (containing an `createdAt` timestamp) to the set method
        // which will update the cookie's `maxAge` property based on the `createdAt` time
        await this.sessionStore.set(req.cookies, res.cookies, {
          ...session
        });
        addCacheControlHeadersForSession(res);
      }

      return res;
    }
  }

  async startInteractiveLogin(
    options: StartInteractiveLoginOptions = {}
  ): Promise<NextResponse> {
    const redirectUri = createRouteUrl(this.routes.callback, this.appBaseUrl); // must be registed with the authorization server
    let returnTo = this.signInReturnToPath;

    // Validate returnTo parameter
    if (options.returnTo) {
      const safeBaseUrl = new URL(
        (this.authorizationParameters.redirect_uri as string | undefined) ||
          this.appBaseUrl
      );
      const sanitizedReturnTo = toSafeRedirect(options.returnTo, safeBaseUrl);

      if (sanitizedReturnTo) {
        returnTo =
          sanitizedReturnTo.pathname +
          sanitizedReturnTo.search +
          sanitizedReturnTo.hash;
      }
    }

    // Generate PKCE challenges
    const codeChallengeMethod = "S256";
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
    const state = oauth.generateRandomState();
    const nonce = oauth.generateRandomNonce();

    // Construct base authorization parameters
    const authorizationParams = new URLSearchParams();
    authorizationParams.set("client_id", this.clientMetadata.client_id);
    authorizationParams.set("redirect_uri", redirectUri.toString());
    authorizationParams.set("response_type", "code");
    authorizationParams.set("code_challenge", codeChallenge);
    authorizationParams.set("code_challenge_method", codeChallengeMethod);
    authorizationParams.set("state", state);
    authorizationParams.set("nonce", nonce);

    const mergedAuthorizationParams: AuthorizationParameters = {
      // any custom params to forward to /authorize defined as configuration
      ...this.authorizationParameters,
      // custom parameters passed in via the query params to ensure only the confidential client can set them
      ...options.authorizationParameters
    };

    Object.entries(mergedAuthorizationParams).forEach(([key, val]) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key) && val != null) {
        authorizationParams.set(key, String(val));
      }
    });

    // Prepare transaction state
    const transactionState: TransactionState = {
      nonce,
      maxAge: this.authorizationParameters.max_age,
      codeVerifier,
      responseType: "code",
      state,
      returnTo
    };

    // Generate authorization URL with PAR handling
    const [error, authorizationUrl] =
      await this.authorizationUrl(authorizationParams);
    if (error) {
      return new NextResponse(
        "An error occured while trying to initiate the login request.",
        {
          status: 500
        }
      );
    }

    // Set response and save transaction
    const res = NextResponse.redirect(authorizationUrl.toString());
    await this.transactionStore.save(res.cookies, transactionState);

    return res;
  }

  async handleLogin(req: NextRequest): Promise<NextResponse> {
    const searchParams = Object.fromEntries(req.nextUrl.searchParams.entries());
    const options: StartInteractiveLoginOptions = {
      // SECURITY CRITICAL: Only forward query params when PAR is disabled
      authorizationParameters: !this.pushedAuthorizationRequests
        ? searchParams
        : {},
      returnTo: searchParams.returnTo
    };
    return this.startInteractiveLogin(options);
  }

  async handleLogout(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies);
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      // Clean up session on discovery error
      const errorResponse = new NextResponse(
        "An error occured while trying to initiate the logout request.",
        {
          status: 500
        }
      );
      await this.sessionStore.delete(req.cookies, errorResponse.cookies);
      await this.transactionStore.deleteAll(req.cookies, errorResponse.cookies);
      return errorResponse;
    }

    const returnTo =
      req.nextUrl.searchParams.get("returnTo") || this.appBaseUrl;

    const createV2LogoutResponse = (): NextResponse => {
      const url = new URL("/v2/logout", this.issuer);
      url.searchParams.set("returnTo", returnTo);
      url.searchParams.set("client_id", this.clientMetadata.client_id);
      return NextResponse.redirect(url);
    };

    const createOIDCLogoutResponse = (): NextResponse => {
      const url = new URL(authorizationServerMetadata.end_session_endpoint!);
      url.searchParams.set("client_id", this.clientMetadata.client_id);
      url.searchParams.set("post_logout_redirect_uri", returnTo);

      if (session?.internal.sid) {
        url.searchParams.set("logout_hint", session.internal.sid);
      }

      if (session?.tokenSet.idToken) {
        url.searchParams.set("id_token_hint", session.tokenSet.idToken);
      }

      return NextResponse.redirect(url);
    };

    // Determine logout strategy and create appropriate response
    let logoutResponse: NextResponse;

    if (this.logoutStrategy === "v2") {
      // Always use v2 logout endpoint
      logoutResponse = createV2LogoutResponse();
    } else if (this.logoutStrategy === "oidc") {
      // Always use OIDC RP-Initiated Logout
      if (!authorizationServerMetadata.end_session_endpoint) {
        // Clean up session on OIDC error
        const errorResponse = new NextResponse(
          "OIDC RP-Initiated Logout is not supported by the authorization server. Enable it or use a different logout strategy.",
          {
            status: 500
          }
        );
        await this.sessionStore.delete(req.cookies, errorResponse.cookies);
        await this.transactionStore.deleteAll(
          req.cookies,
          errorResponse.cookies
        );
        return errorResponse;
      }
      logoutResponse = createOIDCLogoutResponse();
    } else {
      // Auto strategy (default): Try OIDC first, fallback to v2 if not available
      if (!authorizationServerMetadata.end_session_endpoint) {
        console.warn(
          "The Auth0 client does not have RP-initiated logout enabled, the user will be redirected to the `/v2/logout` endpoint instead. Learn how to enable it here: https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#enable-endpoint-discovery"
        );
        logoutResponse = createV2LogoutResponse();
      } else {
        logoutResponse = createOIDCLogoutResponse();
      }
    }

    // Clean up session and transaction cookies
    await this.sessionStore.delete(req.cookies, logoutResponse.cookies);
    addCacheControlHeadersForSession(logoutResponse);

    // Clear any orphaned transaction cookies
    await this.transactionStore.deleteAll(req.cookies, logoutResponse.cookies);

    return logoutResponse;
  }

  async handleCallback(req: NextRequest): Promise<NextResponse> {
    const state = req.nextUrl.searchParams.get("state");
    if (!state) {
      return this.onCallback(new MissingStateError(), {}, null);
    }

    const transactionStateCookie = await this.transactionStore.get(
      req.cookies,
      state
    );
    if (!transactionStateCookie) {
      return this.onCallback(new InvalidStateError(), {}, null);
    }

    const transactionState = transactionStateCookie.payload;
    const onCallbackCtx: OnCallbackContext = {
      returnTo: transactionState.returnTo
    };

    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      return this.onCallback(discoveryError, onCallbackCtx, null);
    }

    let codeGrantParams: URLSearchParams;
    try {
      codeGrantParams = oauth.validateAuthResponse(
        authorizationServerMetadata,
        this.clientMetadata,
        req.nextUrl.searchParams,
        transactionState.state
      );
    } catch (e: any) {
      return this.onCallback(
        new AuthorizationError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description
          })
        }),
        onCallbackCtx,
        null
      );
    }

    let codeGrantResponse: Response;
    try {
      const redirectUri = createRouteUrl(this.routes.callback, this.appBaseUrl); // must be registed with the authorization server
      codeGrantResponse = await oauth.authorizationCodeGrantRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        await this.getClientAuth(),
        codeGrantParams,
        redirectUri.toString(),
        transactionState.codeVerifier,
        {
          ...this.httpOptions(),
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests
        }
      );
    } catch (e: any) {
      return this.onCallback(
        new AuthorizationCodeGrantRequestError(e.message),
        onCallbackCtx,
        null
      );
    }

    let oidcRes: oauth.TokenEndpointResponse;
    try {
      oidcRes = await oauth.processAuthorizationCodeResponse(
        authorizationServerMetadata,
        this.clientMetadata,
        codeGrantResponse,
        {
          expectedNonce: transactionState.nonce,
          maxAge: transactionState.maxAge,
          requireIdToken: true
        }
      );
    } catch (e: any) {
      return this.onCallback(
        new AuthorizationCodeGrantError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description
          })
        }),
        onCallbackCtx,
        null
      );
    }

    const idTokenClaims = oauth.getValidatedIdTokenClaims(oidcRes)!;
    let session: SessionData = {
      user: idTokenClaims,
      tokenSet: {
        accessToken: oidcRes.access_token,
        idToken: oidcRes.id_token,
        scope: oidcRes.scope,
        refreshToken: oidcRes.refresh_token,
        expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in)
      },
      internal: {
        sid: idTokenClaims.sid as string,
        createdAt: Math.floor(Date.now() / 1000)
      }
    };

    const res = await this.onCallback(null, onCallbackCtx, session);

    // call beforeSessionSaved callback if present
    // if not then filter id_token claims with default rules
    session = await this.finalizeSession(session, oidcRes.id_token);

    await this.sessionStore.set(req.cookies, res.cookies, session, true);
    addCacheControlHeadersForSession(res);
    await this.transactionStore.delete(res.cookies, state);

    return res;
  }

  async handleProfile(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies);

    if (!session) {
      if (this.noContentProfileResponseWhenUnauthenticated) {
        return new NextResponse(null, {
          status: 204
        });
      }

      return new NextResponse(null, {
        status: 401
      });
    }
    const res = NextResponse.json(session?.user);
    addCacheControlHeadersForSession(res);
    return res;
  }

  async handleAccessToken(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies);

    if (!session) {
      return NextResponse.json(
        {
          error: {
            message: "The user does not have an active session.",
            code: AccessTokenErrorCode.MISSING_SESSION
          }
        },
        {
          status: 401
        }
      );
    }

    const [error, getTokenSetResponse] = await this.getTokenSet(
      session.tokenSet
    );

    if (error) {
      return NextResponse.json(
        {
          error: {
            message: error.message,
            code: error.code
          }
        },
        {
          status: 401
        }
      );
    }

    const { tokenSet: updatedTokenSet, idTokenClaims } = getTokenSetResponse;

    const res = NextResponse.json({
      token: updatedTokenSet.accessToken,
      scope: updatedTokenSet.scope,
      expires_at: updatedTokenSet.expiresAt
    });

    if (
      updatedTokenSet.accessToken !== session.tokenSet.accessToken ||
      updatedTokenSet.expiresAt !== session.tokenSet.expiresAt ||
      updatedTokenSet.refreshToken !== session.tokenSet.refreshToken
    ) {
      if (idTokenClaims) {
        session.user = idTokenClaims as User;
      }
      // call beforeSessionSaved callback if present
      // if not then filter id_token claims with default rules
      const finalSession = await this.finalizeSession(
        session,
        updatedTokenSet.idToken
      );
      await this.sessionStore.set(req.cookies, res.cookies, {
        ...finalSession,
        tokenSet: updatedTokenSet
      });
      addCacheControlHeadersForSession(res);
    }

    return res;
  }

  async handleBackChannelLogout(req: NextRequest): Promise<NextResponse> {
    if (!this.sessionStore.store) {
      return new NextResponse("A session data store is not configured.", {
        status: 500
      });
    }

    if (!this.sessionStore.store.deleteByLogoutToken) {
      return new NextResponse(
        "Back-channel logout is not supported by the session data store.",
        {
          status: 500
        }
      );
    }

    const body = new URLSearchParams(await req.text());
    const logoutToken = body.get("logout_token");

    if (!logoutToken) {
      return new NextResponse("Missing `logout_token` in the request body.", {
        status: 400
      });
    }

    const [error, logoutTokenClaims] =
      await this.verifyLogoutToken(logoutToken);
    if (error) {
      return new NextResponse(error.message, {
        status: 400
      });
    }

    await this.sessionStore.store.deleteByLogoutToken(logoutTokenClaims);

    return new NextResponse(null, {
      status: 204
    });
  }

  /**
   * Retrieves OAuth token sets, handling token refresh when necessary or if forced.
   *
   * @returns A tuple containing either:
   *   - `[SdkError, null]` if an error occurred (missing refresh token, discovery failure, or refresh failure)
   *   - `[null, {tokenSet, idTokenClaims}]` if a new token was retrieved, containing the new token set ID token claims
   *   - `[null, {tokenSet, }]` if token refresh was not done and existing token was returned
   */
  async getTokenSet(
    tokenSet: TokenSet,
    forceRefresh?: boolean | undefined
  ): Promise<[null, GetTokenSetResponse] | [SdkError, null]> {
    // the access token has expired but we do not have a refresh token
    if (!tokenSet.refreshToken && tokenSet.expiresAt <= Date.now() / 1000) {
      return [
        new AccessTokenError(
          AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
          "The access token has expired and a refresh token was not provided. The user needs to re-authenticate."
        ),
        null
      ];
    }

    if (tokenSet.refreshToken) {
      // either the access token has expired or we are forcing a refresh
      if (forceRefresh || tokenSet.expiresAt <= Date.now() / 1000) {
        const [discoveryError, authorizationServerMetadata] =
          await this.discoverAuthorizationServerMetadata();

        if (discoveryError) {
          return [discoveryError, null];
        }

        const refreshTokenRes = await oauth.refreshTokenGrantRequest(
          authorizationServerMetadata,
          this.clientMetadata,
          await this.getClientAuth(),
          tokenSet.refreshToken,
          {
            ...this.httpOptions(),
            [oauth.customFetch]: this.fetch,
            [oauth.allowInsecureRequests]: this.allowInsecureRequests
          }
        );

        let oauthRes: oauth.TokenEndpointResponse;
        try {
          oauthRes = await oauth.processRefreshTokenResponse(
            authorizationServerMetadata,
            this.clientMetadata,
            refreshTokenRes
          );
        } catch (e: any) {
          return [
            new AccessTokenError(
              AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN,
              "The access token has expired and there was an error while trying to refresh it.",
              new OAuth2Error({
                code: e.error,
                message: e.error_description
              })
            ),
            null
          ];
        }

        const idTokenClaims = oauth.getValidatedIdTokenClaims(oauthRes)!;
        const accessTokenExpiresAt =
          Math.floor(Date.now() / 1000) + Number(oauthRes.expires_in);

        const updatedTokenSet = {
          ...tokenSet, // contains the existing `iat` claim to maintain the session lifetime
          accessToken: oauthRes.access_token,
          idToken: oauthRes.id_token,
          expiresAt: accessTokenExpiresAt
        };

        if (oauthRes.refresh_token) {
          // refresh token rotation is enabled, persist the new refresh token from the response
          updatedTokenSet.refreshToken = oauthRes.refresh_token;
        } else {
          // we did not get a refresh token back, keep the current long-lived refresh token around
          updatedTokenSet.refreshToken = tokenSet.refreshToken;
        }

        return [
          null,
          {
            tokenSet: updatedTokenSet,
            idTokenClaims: idTokenClaims
          }
        ];
      }
    }

    return [null, { tokenSet, idTokenClaims: undefined }];
  }

  private async discoverAuthorizationServerMetadata(): Promise<
    [null, oauth.AuthorizationServer] | [SdkError, null]
  > {
    if (this.authorizationServerMetadata) {
      return [null, this.authorizationServerMetadata];
    }

    const issuer = new URL(this.issuer);

    try {
      const authorizationServerMetadata = await oauth
        .discoveryRequest(issuer, {
          ...this.httpOptions(),
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests
        })
        .then((response) => oauth.processDiscoveryResponse(issuer, response));

      this.authorizationServerMetadata = authorizationServerMetadata;

      return [null, authorizationServerMetadata];
    } catch (e) {
      console.error(
        `An error occured while performing the discovery request. issuer=${issuer.toString()}, error:`,
        e
      );
      return [
        new DiscoveryError(
          "Discovery failed for the OpenID Connect configuration."
        ),
        null
      ];
    }
  }

  private async defaultOnCallback(
    error: SdkError | null,
    ctx: OnCallbackContext
  ) {
    if (error) {
      return new NextResponse(error.message, {
        status: 500
      });
    }

    const res = NextResponse.redirect(
      createRouteUrl(ctx.returnTo || "/", this.appBaseUrl)
    );

    return res;
  }

  private async verifyLogoutToken(
    logoutToken: string
  ): Promise<[null, LogoutToken] | [SdkError, null]> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      return [discoveryError, null];
    }

    // only `RS256` is supported for logout tokens
    const ID_TOKEN_SIGNING_ALG = "RS256";

    const keyInput = jose.createRemoteJWKSet(
      new URL(authorizationServerMetadata.jwks_uri!),
      {
        [jose.jwksCache]: this.jwksCache
      }
    );

    const { payload } = await jose.jwtVerify(logoutToken, keyInput, {
      issuer: authorizationServerMetadata.issuer,
      audience: this.clientMetadata.client_id,
      algorithms: [ID_TOKEN_SIGNING_ALG],
      requiredClaims: ["iat"]
    });

    if (!("sid" in payload) && !("sub" in payload)) {
      return [
        new BackchannelLogoutError(
          'either "sid" or "sub" (or both) claims must be present'
        ),
        null
      ];
    }

    if ("sid" in payload && typeof payload.sid !== "string") {
      return [new BackchannelLogoutError('"sid" claim must be a string'), null];
    }

    if ("sub" in payload && typeof payload.sub !== "string") {
      return [new BackchannelLogoutError('"sub" claim must be a string'), null];
    }

    if ("nonce" in payload) {
      return [new BackchannelLogoutError('"nonce" claim is prohibited'), null];
    }

    if (!("events" in payload)) {
      return [new BackchannelLogoutError('"events" claim is missing'), null];
    }

    if (typeof payload.events !== "object" || payload.events === null) {
      return [
        new BackchannelLogoutError('"events" claim must be an object'),
        null
      ];
    }

    if (
      !("http://schemas.openid.net/event/backchannel-logout" in payload.events)
    ) {
      return [
        new BackchannelLogoutError(
          '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
        ),
        null
      ];
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
        null
      ];
    }

    return [
      null,
      {
        sid: payload.sid as string,
        sub: payload.sub
      }
    ];
  }

  private async authorizationUrl(
    params: URLSearchParams
  ): Promise<[null, URL] | [Error, null]> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();
    if (discoveryError) {
      return [discoveryError, null];
    }

    if (
      this.pushedAuthorizationRequests &&
      !authorizationServerMetadata.pushed_authorization_request_endpoint
    ) {
      console.error(
        "The Auth0 tenant does not have pushed authorization requests enabled. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-par"
      );
      return [
        new Error(
          "The authorization server does not support pushed authorization requests."
        ),
        null
      ];
    }

    const authorizationUrl = new URL(
      authorizationServerMetadata.authorization_endpoint!
    );

    if (this.pushedAuthorizationRequests) {
      // push the request params to the authorization server
      const response = await oauth.pushedAuthorizationRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        await this.getClientAuth(),
        params,
        {
          ...this.httpOptions(),
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests
        }
      );

      let parRes: oauth.PushedAuthorizationResponse;
      try {
        parRes = await oauth.processPushedAuthorizationResponse(
          authorizationServerMetadata,
          this.clientMetadata,
          response
        );
      } catch (e: any) {
        return [
          new AuthorizationError({
            cause: new OAuth2Error({
              code: e.error,
              message: e.error_description
            }),
            message: "An error occured while pushing the authorization request."
          }),
          null
        ];
      }

      authorizationUrl.searchParams.set("request_uri", parRes.request_uri);
      authorizationUrl.searchParams.set(
        "client_id",
        this.clientMetadata.client_id
      );

      return [null, authorizationUrl];
    }

    // append the query parameters to the authorization URL for the normal flow
    authorizationUrl.search = params.toString();

    return [null, authorizationUrl];
  }

  private async getClientAuth(): Promise<oauth.ClientAuth> {
    if (!this.clientSecret && !this.clientAssertionSigningKey) {
      throw new Error(
        "The client secret or client assertion signing key must be provided."
      );
    }

    let clientPrivateKey: jose.CryptoKey | undefined = this
      .clientAssertionSigningKey as jose.CryptoKey | undefined;

    if (clientPrivateKey && typeof clientPrivateKey === "string") {
      clientPrivateKey = await jose.importPKCS8(
        clientPrivateKey,
        this.clientAssertionSigningAlg
      );
    }

    return clientPrivateKey
      ? oauth.PrivateKeyJwt(clientPrivateKey as CryptoKey)
      : oauth.ClientSecretPost(this.clientSecret!);
  }

  private get issuer(): string {
    return this.domain.startsWith("http://") ||
      this.domain.startsWith("https://")
      ? this.domain
      : `https://${this.domain}`;
  }

  /**
   * Exchanges a refresh token for an access token for a connection.
   *
   * This method performs a token exchange using the provided refresh token and connection details.
   * It first checks if the refresh token is present in the `tokenSet`. If not, it returns an error.
   * Then, it constructs the necessary parameters for the token exchange request and performs
   * the request to the authorization server's token endpoint.
   *
   * @returns {Promise<[AccessTokenForConnectionError, null] | [null, ConnectionTokenSet]>} A promise that resolves to a tuple.
   *          The first element is either an `AccessTokenForConnectionError` if an error occurred, or `null` if the request was successful.
   *          The second element is either `null` if an error occurred, or a `ConnectionTokenSet` object
   *          containing the access token, expiration time, and scope if the request was successful.
   *
   * @throws {AccessTokenForConnectionError} If the refresh token is missing or if there is an error during the token exchange process.
   */
  async getConnectionTokenSet(
    tokenSet: TokenSet,
    connectionTokenSet: ConnectionTokenSet | undefined,
    options: AccessTokenForConnectionOptions
  ): Promise<
    [AccessTokenForConnectionError, null] | [null, ConnectionTokenSet]
  > {
    // If we do not have a refresh token
    // and we do not have a connection token set in the cache or the one we have is expired,
    // there is noting to retrieve and we return an error.
    if (
      !tokenSet.refreshToken &&
      (!connectionTokenSet || connectionTokenSet.expiresAt <= Date.now() / 1000)
    ) {
      return [
        new AccessTokenForConnectionError(
          AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
          "A refresh token was not present, Connection Access Token requires a refresh token. The user needs to re-authenticate."
        ),
        null
      ];
    }

    // If we do have a refresh token,
    // and we do not have a connection token set in the cache or the one we have is expired,
    // we need to exchange the refresh token for a connection access token.
    if (
      tokenSet.refreshToken &&
      (!connectionTokenSet || connectionTokenSet.expiresAt <= Date.now() / 1000)
    ) {
      const params = new URLSearchParams();

      params.append("connection", options.connection);
      params.append("subject_token_type", SUBJECT_TYPE_REFRESH_TOKEN);
      params.append("subject_token", tokenSet.refreshToken);
      params.append(
        "requested_token_type",
        REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN
      );

      if (options.login_hint) {
        params.append("login_hint", options.login_hint);
      }

      const [discoveryError, authorizationServerMetadata] =
        await this.discoverAuthorizationServerMetadata();

      if (discoveryError) {
        return [discoveryError, null];
      }

      const httpResponse = await oauth.genericTokenEndpointRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        await this.getClientAuth(),
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
        params,
        {
          [oauth.customFetch]: this.fetch,
          [oauth.allowInsecureRequests]: this.allowInsecureRequests
        }
      );

      let tokenEndpointResponse: oauth.TokenEndpointResponse;
      try {
        tokenEndpointResponse = await oauth.processGenericTokenEndpointResponse(
          authorizationServerMetadata,
          this.clientMetadata,
          httpResponse
        );
      } catch (err: any) {
        return [
          new AccessTokenForConnectionError(
            AccessTokenForConnectionErrorCode.FAILED_TO_EXCHANGE,
            "There was an error trying to exchange the refresh token for a connection access token.",
            new OAuth2Error({
              code: err.error,
              message: err.error_description
            })
          ),
          null
        ];
      }

      return [
        null,
        {
          accessToken: tokenEndpointResponse.access_token,
          expiresAt:
            Math.floor(Date.now() / 1000) +
            Number(tokenEndpointResponse.expires_in),
          scope: tokenEndpointResponse.scope,
          connection: options.connection
        }
      ];
    }

    return [null, connectionTokenSet] as [null, ConnectionTokenSet];
  }

  /**
   * Filters and processes ID token claims for a session.
   *
   * If a `beforeSessionSaved` callback is configured, it will be invoked to allow
   * custom processing of the session and ID token. Otherwise, default filtering
   * will be applied to remove standard ID token claims from the user object.
   */
  async finalizeSession(
    session: SessionData,
    idToken?: string
  ): Promise<SessionData> {
    if (this.beforeSessionSaved) {
      const updatedSession = await this.beforeSessionSaved(
        session,
        idToken ?? null
      );
      session = {
        ...updatedSession,
        internal: session.internal
      };
    } else {
      session.user = filterDefaultIdTokenClaims(session.user);
    }
    return session;
  }
}

const encodeBase64 = (input: string) => {
  const unencoded = new TextEncoder().encode(input);
  const CHUNK_SIZE = 0x8000;
  const arr = [];
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(
      // @ts-expect-error Argument of type 'Uint8Array' is not assignable to parameter of type 'number[]'.
      String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE))
    );
  }
  return btoa(arr.join(""));
};

type GetTokenSetResponse = {
  tokenSet: TokenSet;
  idTokenClaims?: { [key: string]: any };
};
