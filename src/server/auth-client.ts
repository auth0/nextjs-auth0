import { NextResponse, type NextRequest } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";
import * as client from "openid-client";

import packageJson from "../../package.json" with { type: "json" };
import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  AuthorizationCodeGrantError,
  AuthorizationCodeGrantRequestError,
  AuthorizationError,
  BackchannelAuthenticationError,
  BackchannelAuthenticationNotSupportedError,
  BackchannelLogoutError,
  ConnectAccountError,
  ConnectAccountErrorCodes,
  DiscoveryError,
  DPoPError,
  DPoPErrorCode,
  InvalidStateError,
  MissingStateError,
  MyAccountApiError,
  OAuth2Error,
  SdkError
} from "../errors/index.js";
import {
  CompleteConnectAccountRequest,
  CompleteConnectAccountResponse,
  ConnectAccountOptions,
  ConnectAccountRequest,
  ConnectAccountResponse
} from "../types/connected-accounts.js";
import { DpopKeyPair, DpopOptions } from "../types/dpop.js";
import {
  AccessTokenForConnectionOptions,
  AccessTokenSet,
  AuthorizationParameters,
  BackchannelAuthenticationOptions,
  BackchannelAuthenticationResponse,
  ConnectionTokenSet,
  GetAccessTokenOptions,
  LogoutStrategy,
  LogoutToken,
  RESPONSE_TYPES,
  SessionData,
  StartInteractiveLoginOptions,
  SUBJECT_TOKEN_TYPES,
  TokenSet,
  User
} from "../types/index.js";
import { mergeAuthorizationParamsIntoSearchParams } from "../utils/authorization-params-helpers.js";
import { DEFAULT_SCOPES } from "../utils/constants.js";
import { withDPoPNonceRetry } from "../utils/dpopUtils.js";
import {
  ensureNoLeadingSlash,
  ensureTrailingSlash,
  normalizeWithBasePath,
  removeTrailingSlash
} from "../utils/pathUtils.js";
import {
  ensureDefaultScope,
  getScopeForAudience
} from "../utils/scope-helpers.js";
import { getSessionChangesAfterGetAccessToken } from "../utils/session-changes-helpers.js";
import {
  compareScopes,
  findAccessTokenSet,
  mergeScopes,
  tokenSetFromAccessTokenSet
} from "../utils/token-set-helpers.js";
import { toSafeRedirect } from "../utils/url-helpers.js";
import { addCacheControlHeadersForSession } from "./cookies.js";
import {
  AccessTokenFactory,
  Fetcher,
  FetcherConfig,
  FetcherHooks,
  FetcherMinimalConfig
} from "./fetcher.js";
import { AbstractSessionStore } from "./session/abstract-session-store.js";
import { TransactionState, TransactionStore } from "./transaction-store.js";
import { filterDefaultIdTokenClaims } from "./user.js";

export type BeforeSessionSavedHook = (
  session: SessionData,
  idToken: string | null
) => Promise<SessionData>;

export type OnCallbackContext = {
  /**
   * The type of response expected from the authorization server.
   * One of {@link RESPONSE_TYPES}
   */
  responseType?: RESPONSE_TYPES;
  /**
   * The URL or path the user should be redirected to after completing the transaction.
   */
  returnTo?: string;
  /**
   * The connected account information when the responseType is {@link RESPONSE_TYPES.CONNECT_CODE}
   */
  connectedAccount?: CompleteConnectAccountResponse;
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
  connectAccount: string;
}
export type RoutesOptions = Partial<
  Pick<
    Routes,
    "login" | "callback" | "logout" | "backChannelLogout" | "connectAccount"
  >
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
  includeIdTokenHintInOIDCLogoutUrl?: boolean;

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
  enableConnectAccountEndpoint?: boolean;

  useDPoP?: boolean;
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;

  /**
   * @future This option is reserved for future implementation.
   * Currently not used - placeholder for upcoming nonce persistence feature.
   */
  // dpopHandleStorage?: DPoPHandleStorageInterface; // Commented out until implementation
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
  private includeIdTokenHintInOIDCLogoutUrl: boolean;

  private beforeSessionSaved?: BeforeSessionSavedHook;
  private onCallback: OnCallbackHook;

  private routes: Routes;

  private fetch: typeof fetch;
  private jwksCache: jose.JWKSCacheInput;
  private allowInsecureRequests: boolean;
  private httpTimeout: number;
  private httpOptions: () => { signal: AbortSignal; headers: Headers };

  private authorizationServerMetadata?: oauth.AuthorizationServer;

  private readonly enableAccessTokenEndpoint: boolean;
  private readonly noContentProfileResponseWhenUnauthenticated: boolean;
  private readonly enableConnectAccountEndpoint: boolean;

  private dpopOptions?: DpopOptions;

  private dpopKeyPair?: DpopKeyPair;
  private readonly useDPoP: boolean;

  constructor(options: AuthClientOptions) {
    // dependencies
    this.fetch = options.fetch || fetch;
    this.jwksCache = options.jwksCache || {};
    this.allowInsecureRequests = options.allowInsecureRequests ?? false;
    this.httpTimeout = options.httpTimeout ?? 5000;
    this.httpOptions = () => {
      const headers = new Headers();
      const enableTelemetry = options.enableTelemetry ?? true;
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
        signal: AbortSignal.timeout(this.httpTimeout),
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

    // Apply DPoP timing validation options to client metadata if provided
    if (options.dpopOptions) {
      if (typeof options.dpopOptions.clockSkew === "number") {
        this.clientMetadata[oauth.clockSkew] = options.dpopOptions.clockSkew;
      }
      if (typeof options.dpopOptions.clockTolerance === "number") {
        this.clientMetadata[oauth.clockTolerance] =
          options.dpopOptions.clockTolerance;
      }
    }

    // Store dpopOptions for use in retry logic
    this.dpopOptions = options.dpopOptions;
    this.clientSecret = options.clientSecret;
    this.authorizationParameters = options.authorizationParameters || {
      scope: DEFAULT_SCOPES
    };
    this.pushedAuthorizationRequests =
      options.pushedAuthorizationRequests ?? false;
    this.clientAssertionSigningKey = options.clientAssertionSigningKey;
    this.clientAssertionSigningAlg =
      options.clientAssertionSigningAlg || "RS256";

    this.authorizationParameters.scope = ensureDefaultScope(
      this.authorizationParameters
    );

    const scope = getScopeForAudience(
      this.authorizationParameters.scope,
      this.authorizationParameters.audience
    )
      ?.split(" ")
      .map((s) => s.trim());
    if (!scope || !scope.includes("openid")) {
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
    this.includeIdTokenHintInOIDCLogoutUrl =
      options.includeIdTokenHintInOIDCLogoutUrl ?? true;

    // hooks
    this.beforeSessionSaved = options.beforeSessionSaved;
    this.onCallback = options.onCallback || this.defaultOnCallback;

    // routes
    this.routes = options.routes;

    this.enableAccessTokenEndpoint = options.enableAccessTokenEndpoint ?? true;
    this.noContentProfileResponseWhenUnauthenticated =
      options.noContentProfileResponseWhenUnauthenticated ?? false;
    this.enableConnectAccountEndpoint =
      options.enableConnectAccountEndpoint ?? false;

    this.useDPoP = options.useDPoP ?? false;

    // Initialize DPoP if enabled. Check useDPoP flag first to avoid timing attacks.
    if ((options.useDPoP ?? false) && options.dpopKeyPair) {
      this.dpopKeyPair = options.dpopKeyPair;
    }
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
    } else if (
      method === "GET" &&
      sanitizedPathname === this.routes.connectAccount &&
      this.enableConnectAccountEndpoint
    ) {
      return this.handleConnectAccount(req);
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
    const redirectUri = createRouteUrl(this.routes.callback, this.appBaseUrl); // must be registered with the authorization server
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
    // If provided on both sides, this does not merge the scope property,
    // instead, the scope from the right side (options) fully overrides the left side.
    // This is done to avoid breaking existing behavior.
    const authorizationParams = mergeAuthorizationParamsIntoSearchParams(
      this.authorizationParameters,
      options.authorizationParameters,
      INTERNAL_AUTHORIZE_PARAMS
    );
    authorizationParams.set("client_id", this.clientMetadata.client_id);
    authorizationParams.set("redirect_uri", redirectUri.toString());
    authorizationParams.set("response_type", RESPONSE_TYPES.CODE);
    authorizationParams.set("code_challenge", codeChallenge);
    authorizationParams.set("code_challenge_method", codeChallengeMethod);
    authorizationParams.set("state", state);
    authorizationParams.set("nonce", nonce);

    // Add dpop_jkt parameter if DPoP is enabled
    if (this.dpopKeyPair) {
      try {
        const publicKeyJwk = await jose.exportJWK(this.dpopKeyPair.publicKey);
        const dpopJkt = await jose.calculateJwkThumbprint(publicKeyJwk);
        authorizationParams.set("dpop_jkt", dpopJkt);
      } catch (error) {
        throw new DPoPError(
          DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED,
          "DPoP is enabled but failed to calculate key thumbprint (dpop_jkt). " +
            "This is required for secure DPoP binding. Please check your key configuration.",
          error instanceof Error ? error : undefined
        );
      }
    }

    // Prepare transaction state
    const transactionState: TransactionState = {
      nonce,
      maxAge: this.authorizationParameters.max_age,
      codeVerifier,
      responseType: RESPONSE_TYPES.CODE,
      state,
      returnTo,
      scope: authorizationParams.get("scope") || undefined,
      audience: authorizationParams.get("audience") || undefined
    };

    // Generate authorization URL with PAR handling
    const [error, authorizationUrl] =
      await this.authorizationUrl(authorizationParams);
    if (error) {
      return new NextResponse(
        "An error occurred while trying to initiate the login request.",
        {
          status: 500
        }
      );
    }

    // Set response and save transaction
    const res = NextResponse.redirect(authorizationUrl.toString());

    // Save transaction state
    await this.transactionStore.save(res.cookies, transactionState);

    return res;
  }

  async handleLogin(req: NextRequest): Promise<NextResponse> {
    const searchParams = Object.fromEntries(req.nextUrl.searchParams.entries());

    // Always forward all parameters
    // When PAR is disabled, parameters go to authorization URL as before
    // When PAR is enabled, all parameters are sent securely in the PAR request body

    // do not pass returnTo as part of authorizationParameters
    // returnTo should only be used in txn state
    const { returnTo, ...authorizationParameters } = searchParams;

    const options: StartInteractiveLoginOptions = {
      authorizationParameters,
      returnTo: returnTo
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
        "An error occurred while trying to initiate the logout request.",
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
    const federated = req.nextUrl.searchParams.has("federated");

    const createV2LogoutResponse = (): NextResponse => {
      const url = new URL("/v2/logout", this.issuer);
      url.searchParams.set("returnTo", returnTo);
      url.searchParams.set("client_id", this.clientMetadata.client_id);

      if (federated) {
        url.searchParams.set("federated", "");
      }

      return NextResponse.redirect(url);
    };

    const createOIDCLogoutResponse = (): NextResponse => {
      const url = new URL(authorizationServerMetadata.end_session_endpoint!);
      url.searchParams.set("client_id", this.clientMetadata.client_id);
      url.searchParams.set("post_logout_redirect_uri", returnTo);

      if (session?.internal.sid) {
        url.searchParams.set("logout_hint", session.internal.sid);
      }

      if (this.includeIdTokenHintInOIDCLogoutUrl && session?.tokenSet.idToken) {
        url.searchParams.set("id_token_hint", session.tokenSet.idToken);
      }

      if (federated) {
        url.searchParams.set("federated", "");
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
      return this.handleCallbackError(new MissingStateError(), {}, req);
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
      responseType: transactionState.responseType,
      returnTo: transactionState.returnTo
    };

    if (transactionState.responseType === RESPONSE_TYPES.CONNECT_CODE) {
      const session = await this.sessionStore.get(req.cookies);

      if (!session) {
        return this.handleCallbackError(
          new ConnectAccountError({
            code: ConnectAccountErrorCodes.MISSING_SESSION,
            message: "The user does not have an active session."
          }),
          onCallbackCtx,
          req,
          state
        );
      }

      // get an access token for connected accounts
      const [tokenSetError, tokenSetResponse] = await this.getTokenSet(
        session,
        {
          audience: `${this.issuer}/me/`,
          scope: "create:me:connected_accounts"
        }
      );

      if (tokenSetError) {
        return this.handleCallbackError(
          tokenSetError,
          onCallbackCtx,
          req,
          state
        );
      }

      const [completeConnectAccountError, connectedAccount] =
        await this.completeConnectAccount({
          tokenSet: tokenSetResponse.tokenSet,
          authSession: transactionState.authSession!,
          connectCode: req.nextUrl.searchParams.get("connect_code")!,
          redirectUri: createRouteUrl(
            this.routes.callback,
            this.appBaseUrl
          ).toString(),
          codeVerifier: transactionState.codeVerifier
        });

      if (completeConnectAccountError) {
        return this.handleCallbackError(
          completeConnectAccountError,
          onCallbackCtx,
          req,
          state
        );
      }

      const res = await this.onCallback(
        null,
        {
          ...onCallbackCtx,
          connectedAccount
        },
        session
      );

      await this.transactionStore.delete(res.cookies, state);

      return res;
    }

    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      return this.handleCallbackError(
        discoveryError,
        onCallbackCtx,
        req,
        state
      );
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
      return this.handleCallbackError(
        new AuthorizationError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description
          })
        }),
        onCallbackCtx,
        req,
        state
      );
    }

    let codeGrantResponse: Response;
    let redirectUri: URL;
    let authorizationCodeGrantRequestCall: () => Promise<Response>;

    try {
      redirectUri = createRouteUrl(this.routes.callback, this.appBaseUrl); // must be registered with the authorization server
      authorizationCodeGrantRequestCall = async () =>
        oauth.authorizationCodeGrantRequest(
          authorizationServerMetadata,
          this.clientMetadata,
          await this.getClientAuth(),
          codeGrantParams,
          redirectUri.toString(),
          transactionState.codeVerifier,
          {
            ...this.httpOptions(),
            [oauth.customFetch]: this.fetch,
            [oauth.allowInsecureRequests]: this.allowInsecureRequests,
            ...(this.useDPoP &&
              this.dpopKeyPair && {
                DPoP: oauth.DPoP(this.clientMetadata, this.dpopKeyPair!)
              })
          }
        );

      codeGrantResponse = await authorizationCodeGrantRequestCall();
    } catch (e: any) {
      return this.handleCallbackError(
        new AuthorizationCodeGrantRequestError(e.message),
        onCallbackCtx,
        req,
        state
      );
    }
    let oidcRes: oauth.TokenEndpointResponse;
    try {
      // Process the authorization code response
      // For authorization code flows, oauth4webapi handles DPoP nonce management internally
      // No need for manual retry since authorization codes are single-use
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
      return this.handleCallbackError(
        new AuthorizationCodeGrantError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description
          })
        }),
        onCallbackCtx,
        req,
        state
      );
    }

    const idTokenClaims = oauth.getValidatedIdTokenClaims(oidcRes)!;
    let session: SessionData = {
      user: idTokenClaims,
      tokenSet: {
        accessToken: oidcRes.access_token,
        idToken: oidcRes.id_token,
        scope: oidcRes.scope,
        requestedScope: transactionState.scope,
        audience: transactionState.audience,
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

    // Clean up the current transaction cookie after successful authentication
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
    const audience = req.nextUrl.searchParams.get("audience");
    const scope = req.nextUrl.searchParams.get("scope");

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

    const [error, getTokenSetResponse] = await this.getTokenSet(session, {
      scope,
      audience
    });

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
      expires_at: updatedTokenSet.expiresAt,
      ...(updatedTokenSet.token_type && {
        token_type: updatedTokenSet.token_type
      })
    });

    const sessionChanges = getSessionChangesAfterGetAccessToken(
      session,
      updatedTokenSet,
      {
        scope: this.authorizationParameters?.scope,
        audience: this.authorizationParameters?.audience
      }
    );

    if (sessionChanges) {
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
        ...sessionChanges
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

  async handleConnectAccount(req: NextRequest): Promise<NextResponse> {
    const session = await this.sessionStore.get(req.cookies);

    // pass all query params except `connection` and `returnTo` as authorization params
    const connection = req.nextUrl.searchParams.get("connection");
    const returnTo = req.nextUrl.searchParams.get("returnTo") ?? undefined;
    const authorizationParams = Object.fromEntries(
      [...req.nextUrl.searchParams.entries()].filter(
        ([key]) => key !== "connection" && key !== "returnTo"
      )
    );

    if (!connection) {
      return new NextResponse("A connection is required.", {
        status: 400
      });
    }

    if (!session) {
      return new NextResponse("The user does not have an active session.", {
        status: 401
      });
    }

    const [getTokenSetError, getTokenSetResponse] = await this.getTokenSet(
      session,
      {
        scope: "create:me:connected_accounts",
        audience: `${this.issuer}/me/`
      }
    );

    if (getTokenSetError) {
      return new NextResponse(
        "Failed to retrieve a connected account access token.",
        {
          status: 401
        }
      );
    }

    const { tokenSet, idTokenClaims } = getTokenSetResponse;
    const [connectAccountError, connectAccountResponse] =
      await this.connectAccount({
        tokenSet: tokenSet,
        connection,
        authorizationParams,
        returnTo
      });

    if (connectAccountError) {
      return new NextResponse(connectAccountError.message, {
        status: connectAccountError.cause?.status ?? 500
      });
    }

    // update the session with the new token set, if necessary
    const sessionChanges = getSessionChangesAfterGetAccessToken(
      session,
      tokenSet,
      {
        scope: this.authorizationParameters?.scope ?? DEFAULT_SCOPES,
        audience: this.authorizationParameters?.audience
      }
    );

    if (sessionChanges) {
      if (idTokenClaims) {
        session.user = idTokenClaims as User;
      }
      // call beforeSessionSaved callback if present
      // if not then filter id_token claims with default rules
      const finalSession = await this.finalizeSession(
        session,
        tokenSet.idToken
      );
      await this.sessionStore.set(req.cookies, connectAccountResponse.cookies, {
        ...finalSession,
        ...sessionChanges
      });
      addCacheControlHeadersForSession(connectAccountResponse);
    }

    return connectAccountResponse;
  }

  /**
   * Retrieves the token set from the session data, considering optional audience and scope parameters.
   * When audience and scope are provided, it checks if they match the global ones defined in the authorization parameters.
   * If they match, it returns the top-level token set from the session data.
   * If they don't match, it searches for a corresponding access token in the session's `accessTokens` array.
   * @param sessionData The session data containing the token sets.
   * @param options Optional parameters for audience and scope to filter the token set.
   * @returns A partial token set that matches the provided audience and scope, or the top-level token set if they match the global ones.
   */
  #getTokenSetFromSession(
    session: SessionData,
    options: { scope: string; audience?: string | null }
  ): Partial<TokenSet> {
    const tokenSet: Partial<TokenSet> = session.tokenSet;
    const audience = options.audience;
    const scope = options.scope;

    // When audience and scope are provided, we need to compare them with the original ones provided in either the `SessionData.tokenSet` itself, or the Auth0Client constructor.
    // When they are identical, we should read from the top-level `SessionData.tokenSet`.
    // If not, we should look for the corresponding access token in `SessionData.accessTokens`
    const isAudienceTheGlobalAudience =
      !audience ||
      audience === (tokenSet.audience || this.authorizationParameters.audience);

    const isScopeTheGlobalScope =
      !scope ||
      compareScopes(
        tokenSet.requestedScope ||
          getScopeForAudience(this.authorizationParameters.scope, audience),
        scope
      );

    if (isAudienceTheGlobalAudience && isScopeTheGlobalScope) {
      return tokenSet;
    }

    let accessTokenSet: AccessTokenSet | undefined;

    // If there is an audience, we can search for the correct access token in the array
    // If there is no audience, we cannot find the correct access token in the array
    if (audience) {
      accessTokenSet = findAccessTokenSet(session, { scope, audience });
    }

    // Convert the Access Token Set to a Token Set, which mostly ensures the Id Token and RefreshToken are also available,
    // But the access token, expiresAt, audience and scope are taken from the Access Token Set.
    // When no audience was found, we will return an empty Token Set with only the Id Token and Refresh Token
    return tokenSetFromAccessTokenSet(accessTokenSet, tokenSet);
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
    sessionData: SessionData,
    options: GetAccessTokenOptions = {}
  ): Promise<[null, GetTokenSetResponse] | [SdkError, null]> {
    // This will merge the scopes from the authorization parameters and the options.
    // The scope from the options will be added to the scopes from the authorization parameters.
    // If there are duplicate scopes, they will be removed.
    const scope = mergeScopes(
      getScopeForAudience(
        this.authorizationParameters.scope,
        options.audience ?? this.authorizationParameters.audience
      ),
      options.scope
    );

    const tokenSet: Partial<TokenSet> = this.#getTokenSetFromSession(
      sessionData,
      {
        scope: scope,
        audience: options.audience ?? this.authorizationParameters.audience
      }
    );

    // no access token was found that matches the, optional, provided audience and scope
    if (!tokenSet.refreshToken && !tokenSet.accessToken) {
      return [
        new AccessTokenError(
          AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
          "No access token found and a refresh token was not provided. The user needs to re-authenticate."
        ),
        null
      ];
    }

    // the access token was found, but it has expired and we do not have a refresh token
    if (
      !tokenSet.refreshToken &&
      tokenSet.accessToken &&
      tokenSet.expiresAt &&
      tokenSet.expiresAt <= Date.now() / 1000
    ) {
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
      if (
        options.refresh ||
        !tokenSet.expiresAt ||
        tokenSet.expiresAt <= Date.now() / 1000
      ) {
        const [discoveryError, authorizationServerMetadata] =
          await this.discoverAuthorizationServerMetadata();

        if (discoveryError) {
          return [discoveryError, null];
        }

        const additionalParameters = new URLSearchParams();

        if (options.scope) {
          additionalParameters.append("scope", scope);
        }

        if (options.audience) {
          additionalParameters.append("audience", options.audience);
        }

        const refreshTokenGrantRequestCall = async () =>
          oauth.refreshTokenGrantRequest(
            authorizationServerMetadata,
            this.clientMetadata,
            await this.getClientAuth(),
            tokenSet.refreshToken!,
            {
              ...this.httpOptions(),
              [oauth.customFetch]: this.fetch,
              [oauth.allowInsecureRequests]: this.allowInsecureRequests,
              additionalParameters,
              ...(this.useDPoP &&
                this.dpopKeyPair && {
                  DPoP: oauth.DPoP(this.clientMetadata, this.dpopKeyPair!)
                })
            }
          );

        const processRefreshTokenResponseCall = (response: Response) =>
          oauth.processRefreshTokenResponse(
            authorizationServerMetadata,
            this.clientMetadata,
            response
          );

        let oauthRes: oauth.TokenEndpointResponse;
        try {
          oauthRes = await withDPoPNonceRetry(async () => {
            const refreshTokenRes = await refreshTokenGrantRequestCall();
            return await processRefreshTokenResponseCall(refreshTokenRes);
          }, this.dpopOptions?.retry);
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
          // We store the both requested and granted scopes on the tokenSet, so we know what scopes were requested.
          // The server may return less scopes than requested.
          // This ensures we can return the same token again when a token for the same or less scopes is requested by using `requestedScope` during look-up.
          //
          // E.g. When requesting a token with scope `a b`, and we return one for scope `a` only,
          // - If we only store the returned scopes, we cannot return this token when the user requests a token for scope `a b` again.
          // - If we only store the requested scopes, we lose track of the actual scopes granted.
          //
          // Scopes actually granted by the server
          scope: oauthRes.scope,
          // Scopes requested by the client
          requestedScope: scope,
          expiresAt: accessTokenExpiresAt,
          // Keep the audience if it exists, otherwise use the one from the options.
          // If not provided, use `undefined`.
          audience: tokenSet.audience || options.audience || undefined,
          // Store the token type from the OAuth response (e.g., "Bearer", "DPoP")
          ...(oauthRes.token_type && { token_type: oauthRes.token_type })
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

    return [null, { tokenSet: tokenSet as TokenSet, idTokenClaims: undefined }];
  }

  async backchannelAuthentication(
    options: BackchannelAuthenticationOptions
  ): Promise<[null, BackchannelAuthenticationResponse] | [SdkError, null]> {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();
    if (discoveryError) {
      return [discoveryError, null];
    }

    if (!authorizationServerMetadata.backchannel_authentication_endpoint) {
      return [new BackchannelAuthenticationNotSupportedError(), null];
    }

    // If provided on both sides, this does not merge the scope property,
    // instead, the scope from the right side (options) fully overrides the left side.
    // This is done to avoid breaking existing behavior.
    const authorizationParams = mergeAuthorizationParamsIntoSearchParams(
      this.authorizationParameters,
      options.authorizationParams,
      INTERNAL_AUTHORIZE_PARAMS
    );

    if (!authorizationParams.get("scope")) {
      authorizationParams.set("scope", DEFAULT_SCOPES);
    }

    authorizationParams.set("client_id", this.clientMetadata.client_id);
    authorizationParams.set("binding_message", options.bindingMessage);
    authorizationParams.set(
      "login_hint",
      JSON.stringify({
        format: "iss_sub",
        iss: authorizationServerMetadata.issuer,
        sub: options.loginHint.sub
      })
    );

    if (options.requestedExpiry) {
      authorizationParams.append(
        "requested_expiry",
        options.requestedExpiry.toString()
      );
    }

    if (options.authorizationDetails) {
      authorizationParams.append(
        "authorization_details",
        JSON.stringify(options.authorizationDetails)
      );
    }

    const [openIdClientConfigError, openidClientConfig] =
      await this.getOpenIdClientConfig();

    if (openIdClientConfigError) {
      return [openIdClientConfigError, null];
    }

    try {
      const backchannelAuthenticationResponse =
        await client.initiateBackchannelAuthentication(
          openidClientConfig,
          authorizationParams
        );

      const tokenEndpointResponse =
        await client.pollBackchannelAuthenticationGrant(
          openidClientConfig,
          backchannelAuthenticationResponse
        );

      const accessTokenExpiresAt =
        Math.floor(Date.now() / 1000) +
        Number(tokenEndpointResponse.expires_in);

      return [
        null,
        {
          tokenSet: {
            accessToken: tokenEndpointResponse.access_token,
            idToken: tokenEndpointResponse.id_token,
            scope: tokenEndpointResponse.scope,
            refreshToken: tokenEndpointResponse.refresh_token,
            expiresAt: accessTokenExpiresAt
          },
          idTokenClaims: tokenEndpointResponse.claims(),
          authorizationDetails: tokenEndpointResponse.authorization_details
        }
      ];
    } catch (e: any) {
      return [
        new BackchannelAuthenticationError({
          cause: new OAuth2Error({
            code: e.error,
            message: e.error_description
          })
        }),
        null
      ];
    }
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
        `An error occurred while performing the discovery request. issuer=${issuer.toString()}, error:`,
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

  /**
   * Handle callback errors with transaction cleanup
   */
  private async handleCallbackError(
    error: SdkError,
    ctx: OnCallbackContext,
    req: NextRequest,
    state?: string
  ): Promise<NextResponse> {
    const response = await this.onCallback(error, ctx, null);

    // Clean up the transaction cookie on error to prevent accumulation
    if (state) {
      await this.transactionStore.delete(response.cookies, state);
    }

    return response;
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
            message:
              "An error occurred while pushing the authorization request."
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
    // there is nothing to retrieve and we return an error.
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

      const subjectTokenType =
        options.subject_token_type ??
        SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_REFRESH_TOKEN;

      const subjectToken =
        subjectTokenType === SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN
          ? tokenSet.accessToken
          : tokenSet.refreshToken;

      params.append("subject_token_type", subjectTokenType);
      params.append("subject_token", subjectToken);

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

      const genericTokenEndpointRequestCall = async () =>
        oauth.genericTokenEndpointRequest(
          authorizationServerMetadata,
          this.clientMetadata,
          await this.getClientAuth(),
          GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
          params,
          {
            [oauth.customFetch]: this.fetch,
            [oauth.allowInsecureRequests]: this.allowInsecureRequests,
            ...(this.useDPoP &&
              this.dpopKeyPair && {
                DPoP: oauth.DPoP(this.clientMetadata, this.dpopKeyPair!)
              })
          }
        );

      const processGenericTokenEndpointResponseCall = (response: Response) =>
        oauth.processGenericTokenEndpointResponse(
          authorizationServerMetadata,
          this.clientMetadata,
          response
        );

      let tokenEndpointResponse: oauth.TokenEndpointResponse;
      try {
        tokenEndpointResponse = await withDPoPNonceRetry(async () => {
          const httpResponse = await genericTokenEndpointRequestCall();
          return await processGenericTokenEndpointResponseCall(httpResponse);
        }, this.dpopOptions?.retry);
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

  /**
   * Initiates the connect account flow for linking a third-party account to the user's profile.
   * The user will be redirected to authorize the connection.
   */
  async connectAccount(
    options: ConnectAccountOptions & { tokenSet: TokenSet }
  ): Promise<[ConnectAccountError, null] | [null, NextResponse]> {
    const redirectUri = createRouteUrl(this.routes.callback, this.appBaseUrl);
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

    const [error, connectAccountResponse] =
      await this.createConnectAccountTicket({
        tokenSet: options.tokenSet,
        connection: options.connection,
        redirectUri: redirectUri.toString(),
        state,
        codeChallenge,
        codeChallengeMethod,
        authorizationParams: options.authorizationParams
      });

    if (error) {
      return [error, null];
    }

    const transactionState: TransactionState = {
      codeVerifier,
      responseType: RESPONSE_TYPES.CONNECT_CODE,
      state,
      returnTo,
      authSession: connectAccountResponse.authSession
    };

    const res = NextResponse.redirect(
      `${connectAccountResponse.connectUri}?ticket=${encodeURIComponent(connectAccountResponse.connectParams.ticket)}`
    );

    await this.transactionStore.save(res.cookies, transactionState);

    return [null, res];
  }

  private async createConnectAccountTicket(
    options: ConnectAccountRequest
  ): Promise<[null, ConnectAccountResponse] | [ConnectAccountError, null]> {
    try {
      const connectAccountUrl = new URL(
        "/me/v1/connected-accounts/connect",
        this.issuer
      );

      const fetcher = await this.fetcherFactory({
        useDPoP: this.useDPoP,
        getAccessToken: async () => ({
          accessToken: options.tokenSet.accessToken,
          expiresAt: options.tokenSet.expiresAt || 0,
          scope: options.tokenSet.scope,
          token_type: options.tokenSet.token_type
        })
      });

      const httpOptions = this.httpOptions();
      const headers = new Headers(httpOptions.headers);
      headers.set("Content-Type", "application/json");

      const requestBody = {
        connection: options.connection,
        redirect_uri: options.redirectUri,
        state: options.state,
        code_challenge: options.codeChallenge,
        code_challenge_method: options.codeChallengeMethod,
        authorization_params: options.authorizationParams
      };

      const res = await fetcher.fetchWithAuth(connectAccountUrl.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(requestBody)
      });

      if (!res.ok) {
        try {
          const errorBody = await res.json();
          return [
            new ConnectAccountError({
              code: ConnectAccountErrorCodes.FAILED_TO_INITIATE,
              message: `The request to initiate the connect account flow failed with status ${res.status}.`,
              cause: new MyAccountApiError({
                type: errorBody.type,
                title: errorBody.title,
                detail: errorBody.detail,
                status: res.status,
                validationErrors: errorBody.validation_errors
              })
            }),
            null
          ];
        } catch (e) {
          return [
            new ConnectAccountError({
              code: ConnectAccountErrorCodes.FAILED_TO_INITIATE,
              message: `The request to initiate the connect account flow failed with status ${res.status}.`
            }),
            null
          ];
        }
      }

      const { connect_uri, connect_params, auth_session, expires_in } =
        await res.json();

      return [
        null,
        {
          connectUri: connect_uri,
          connectParams: connect_params,
          authSession: auth_session,
          expiresIn: expires_in
        }
      ];
    } catch (e: any) {
      return [
        new ConnectAccountError({
          code: ConnectAccountErrorCodes.FAILED_TO_INITIATE,
          message:
            "An unexpected error occurred while trying to initiate the connect account flow."
        }),
        null
      ];
    }
  }

  private async completeConnectAccount(
    options: CompleteConnectAccountRequest
  ): Promise<[null, CompleteConnectAccountResponse] | [SdkError, null]> {
    const completeConnectAccountUrl = new URL(
      "/me/v1/connected-accounts/complete",
      this.issuer
    );

    try {
      const httpOptions = this.httpOptions();
      const headers = new Headers(httpOptions.headers);
      headers.set("Content-Type", "application/json");

      const fetcher = await this.fetcherFactory({
        useDPoP: this.useDPoP,
        getAccessToken: async () => ({
          accessToken: options.tokenSet.accessToken,
          expiresAt: options.tokenSet.expiresAt || 0,
          scope: options.tokenSet.scope,
          token_type: options.tokenSet.token_type
        })
      });

      const requestBody = {
        auth_session: options.authSession,
        connect_code: options.connectCode,
        redirect_uri: options.redirectUri,
        code_verifier: options.codeVerifier
      };

      const res = await fetcher.fetchWithAuth(completeConnectAccountUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(requestBody)
      });

      if (!res.ok) {
        try {
          const errorBody = await res.json();
          return [
            new ConnectAccountError({
              code: ConnectAccountErrorCodes.FAILED_TO_COMPLETE,
              message: `The request to complete the connect account flow failed with status ${res.status}.`,
              cause: new MyAccountApiError({
                type: errorBody.type,
                title: errorBody.title,
                detail: errorBody.detail,
                status: res.status,
                validationErrors: errorBody.validation_errors
              })
            }),
            null
          ];
        } catch (e) {
          return [
            new ConnectAccountError({
              code: ConnectAccountErrorCodes.FAILED_TO_COMPLETE,
              message: `The request to complete the connect account flow failed with status ${res.status}.`
            }),
            null
          ];
        }
      }

      const { id, connection, access_type, scopes, created_at, expires_at } =
        await res.json();

      return [
        null,
        {
          id,
          connection,
          accessType: access_type,
          scopes,
          createdAt: created_at,
          expiresAt: expires_at
        }
      ];
    } catch (e: any) {
      return [
        new ConnectAccountError({
          code: ConnectAccountErrorCodes.FAILED_TO_COMPLETE,
          message:
            "An unexpected error occurred while trying to complete the connect account flow."
        }),
        null
      ];
    }
  }

  private async getOpenIdClientConfig(): Promise<
    [null, client.Configuration] | [SdkError, null]
  > {
    const [discoveryError, authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      return [discoveryError, null];
    }

    const openidClientConfig = new client.Configuration(
      authorizationServerMetadata,
      this.clientMetadata.client_id,
      {},
      await this.getClientAuth()
    );
    const httpOpts = this.httpOptions();
    const telemetryHeaders = new Headers(httpOpts.headers);

    openidClientConfig[client.customFetch] = (...args) => {
      const headers = new Headers(args[1].headers);
      return this.fetch(args[0], {
        ...args[1],
        body: args[1].body as BodyInit | null | undefined,
        headers: new Headers([...telemetryHeaders, ...headers])
      });
    };

    openidClientConfig.timeout = this.httpTimeout;

    if (this.allowInsecureRequests) {
      client.allowInsecureRequests(openidClientConfig);
    }

    return [null, openidClientConfig];
  }

  /**
   * Creates a new Fetcher instance with DPoP support and authentication capabilities.
   *
   * This method creates fetcher-scoped DPoP handles via `oauth.DPoP(this.clientMetadata, this.dpopKeyPair!)`.
   * Each fetcher instance maintains its own DPoP nonce state for isolation and security.
   * It is recommended to create fetchers at module level and reuse them across requests
   *
   * @example Recommended fetcher reuse pattern
   * ```typescript
   * const managementApi = await auth0.fetcherFactory({
   *   baseUrl: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
   *   session: await getSession(req, res)
   * });
   *
   * // Use the same fetcher for multiple requests
   * const users = await managementApi.get('users');
   * const roles = await managementApi.get('roles');
   * ```
   *
   * **DPoP Nonce Management:**
   * - Each fetcher learns and caches nonces from the authorization server
   * - Failed nonce validation triggers automatic retry with updated nonce
   * - Nonce state is isolated between fetcher instances for security
   *
   * @param options Configuration options for the fetcher
   * @returns Promise resolving to a configured Fetcher instance
   * @throws {DPoPError} When DPoP is enabled but no keypair is configured
   */
  async fetcherFactory<TOutput extends Response>(
    options: FetcherFactoryOptions<TOutput>
  ): Promise<Fetcher<TOutput>> {
    if (this.useDPoP && !this.dpopKeyPair) {
      throw new DPoPError(
        DPoPErrorCode.DPOP_CONFIGURATION_ERROR,
        "DPoP is enabled but no keypair is configured."
      );
    }

    // Ensure authorization server metadata is available for oauth4webapi
    const [discoveryError, _authorizationServerMetadata] =
      await this.discoverAuthorizationServerMetadata();

    if (discoveryError) {
      throw discoveryError;
    }

    const fetcherConfig: FetcherConfig<TOutput> = {
      // Fetcher-scoped DPoP handle and nonce management
      dpopHandle:
        this.useDPoP && (options.useDPoP ?? true)
          ? oauth.DPoP(this.clientMetadata, this.dpopKeyPair!)
          : undefined,
      httpOptions: this.httpOptions,
      allowInsecureRequests: this.allowInsecureRequests,
      retryConfig: this.dpopOptions?.retry,
      fetch: options.fetch,
      getAccessToken: options.getAccessToken,
      baseUrl: options.baseUrl
    };

    const fetcherHooks: FetcherHooks = {
      getAccessToken: options.getAccessToken,
      isDpopEnabled: () => options.useDPoP ?? this.useDPoP ?? false
    };

    return new Fetcher<TOutput>(fetcherConfig, fetcherHooks);
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

/**
 * Options for creating a Fetcher instance via the factory method.
 *
 * Includes all FetcherMinimalConfig options plus internal session data.
 * The `nonceStorageId` from FetcherMinimalConfig is included but currently ignored.
 */
export type FetcherFactoryOptions<TOutput extends Response> = {
  useDPoP?: boolean;
  getAccessToken: AccessTokenFactory;
} & FetcherMinimalConfig<TOutput>;
