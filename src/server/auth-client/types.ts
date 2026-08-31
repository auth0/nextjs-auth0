import type { NextResponse } from "next/server.js";
import type * as jose from "jose";
import type * as oauth from "oauth4webapi";

import type { SdkError } from "../../errors/index.js";
import type { CompleteConnectAccountResponse } from "../../types/connected-accounts.js";
import type { DpopKeyPair, DpopOptions } from "../../types/dpop.js";
import type {
  AuthorizationParameters,
  LogoutStrategy,
  RESPONSE_TYPES,
  SessionData,
  TokenSet
} from "../../types/index.js";
import type { AuthClientProvider } from "../auth-client-provider.js";
import type { DiscoveryCache } from "../discovery-cache.js";
import type {
  AccessTokenFactory,
  FetcherMinimalConfig
} from "../fetcher/fetcher.js";
import type { AbstractSessionStore } from "../session/abstract-session-store.js";
import type { TransactionStore } from "../transaction-store.js";

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
   * The resolved base URL for the current request, used to build safe redirects.
   */
  appBaseUrl?: string;
  /**
   * The URL or path the user should be redirected to after completing the transaction.
   */
  returnTo?: string;
  /**
   * The connected account information when the responseType is {@link RESPONSE_TYPES.CONNECT_CODE}
   */
  connectedAccount?: CompleteConnectAccountResponse;
  /**
   * The return strategy for this callback flow.
   * - 'redirect' (default): Standard OAuth redirect flow
   * - 'popup': Popup flow returning via window.postMessage
   * Hook authors can use this to detect popup flows and adapt behavior.
   */
  challengeMode?: "redirect" | "popup";
};
export type OnCallbackHook = (
  error: SdkError | null,
  ctx: OnCallbackContext,
  session: SessionData | null
) => Promise<NextResponse>;

export interface Routes {
  login: string;
  logout: string;
  callback: string;
  profile: string;
  accessToken: string;
  backChannelLogout: string;
  connectAccount: string;
  mfaAuthenticators: string;
  mfaChallenge: string;
  mfaVerify: string;
  mfaAssociate: string;
  passwordlessStart: string;
  passwordlessVerify: string;
  passwordlessDbOtpChallenge: string;
  passwordlessDbGetToken: string;
  passkeyRegister: string;
  passkeyChallenge: string;
  passkeyGetToken: string;
  passkeyEnrollmentChallenge: string;
  passkeyEnrollmentVerify: string;
}
export type RoutesOptions = Partial<Routes>;

/**
 * @private
 */
export interface AuthClientOptions {
  transactionStore: TransactionStore;
  sessionStore: AbstractSessionStore;

  domain: string;
  /**
   * Issuer URL override. When provided, this is used instead of constructing
   * the issuer from the domain hostname. Required for providers like Okta that
   * use path-based authorization server URLs (e.g. https://myorg.okta.com/oauth2/default/).
   */
  issuer?: string;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | jose.CryptoKey;
  clientAssertionSigningAlg?: string;
  authorizationParameters?: AuthorizationParameters;
  pushedAuthorizationRequests?: boolean;

  secret: string;
  /**
   * Normalized appBaseUrl. When omitted, the SDK infers the base URL from the request.
   * If you construct AuthClient directly, normalize the value first.
   */
  appBaseUrl?: string | string[];
  signInReturnToPath?: string;
  logoutStrategy?: LogoutStrategy;
  includeIdTokenHintInOIDCLogoutUrl?: boolean;

  beforeSessionSaved?: BeforeSessionSavedHook;
  onCallback?: OnCallbackHook;

  routes: Routes;

  // custom fetch implementation to allow for dependency injection
  fetch?: typeof fetch;
  discoveryCache?: DiscoveryCache;
  provider?: AuthClientProvider;
  allowInsecureRequests?: boolean;
  httpTimeout?: number;
  enableTelemetry?: boolean;
  enableAccessTokenEndpoint?: boolean;
  noContentProfileResponseWhenUnauthenticated?: boolean;
  enableConnectAccountEndpoint?: boolean;
  tokenRefreshBuffer?: number;

  useDPoP?: boolean;
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;

  /**
   * Enable mTLS (Mutual TLS) client authentication (RFC 8705).
   *
   * When `true`, the SDK uses `oauth.TlsClientAuth()` for client authentication
   * and routes all token requests to the mTLS endpoint aliases advertised in
   * the Auth0 discovery document (`mtls_endpoint_aliases`).
   *
   * Requires the `fetch` option to be set with a TLS-aware implementation
   * (e.g. Node.js `undici` with a client certificate). The standard `fetch`
   * global has no client certificate API.
   *
   * @default false
   */
  useMtls?: boolean;

  /**
   * MFA token TTL in seconds (for token encryption expiration).
   * Default: 300 (5 minutes, matching Auth0's mfa_token expiration)
   */
  mfaTokenTtl?: number;

  /**
   * Content Security Policy nonce for inline scripts.
   * Required when CSP is enabled and popup flows use postMessage return strategy.
   * The nonce is injected into the <script> tag of the postMessage HTML response.
   */
  cspNonce?: string;

  /**
   * @future This option is reserved for future implementation.
   * Currently not used - placeholder for upcoming nonce persistence feature.
   */
  // dpopHandleStorage?: DPoPHandleStorageInterface; // Commented out until implementation
}

/**
 * Options for creating a Fetcher instance via the factory method.
 *
 * Includes all FetcherMinimalConfig options plus internal session data.
 * The `nonceStorageId` from FetcherMinimalConfig is included but currently ignored.
 */
export type FetcherFactoryOptions<TOutput extends Response> = {
  useDPoP?: boolean;
  getAccessToken: AccessTokenFactory;
  dpopHandle?: oauth.DPoPHandle;
} & FetcherMinimalConfig<TOutput>;

export type GetTokenSetResponse = {
  tokenSet: TokenSet;
  idTokenClaims?: { [key: string]: any };
};
