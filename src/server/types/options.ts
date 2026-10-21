import type { IncomingMessage, ServerResponse } from "http";
import type { NextApiRequest, NextApiResponse } from "next/types.js";

import type { DpopKeyPair, DpopOptions } from "../../types/dpop.js";
import type {
  AnonymousSessionConfig,
  AuthorizationParameters,
  LogoutStrategy,
  SessionDataStore
} from "../../types/index.js";
import type { DiscoveryCacheOptions, DomainResolver } from "../../types/mcd.js";
import type { BeforeSessionSavedHook, OnCallbackHook } from "./hooks.js";
import type { RoutesOptions } from "./routes.js";
import type { SessionConfiguration } from "./session.js";
import type { TransactionCookieOptions } from "./transaction.js";

export interface Auth0ClientOptions {
  // authorization server configuration
  /**
   * The Auth0 domain for the tenant.
   *
   * - `string`: Static domain (e.g., `"example.us.auth0.com"`). Existing behavior preserved.
   * - `DomainResolver`: Async function resolving domain per-request from headers.
   *   Enables Multiple Custom Domains (MCD) for B2C multi-brand, B2B SaaS, or domain migration.
   *
   * Falls back to `AUTH0_DOMAIN` environment variable if not provided.
   *
   * @see {@link DomainResolver} for resolver signature and examples.
   * @see [MCD Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#multiple-custom-domains-mcd)
   */
  domain?: string | DomainResolver;
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
   * Can be a single URL string, or an array of allowed base URLs. When an array is
   * provided, the SDK validates the incoming request origin against the list and uses
   * the matching entry (allow-list mode). This is useful for multi-domain or preview
   * deployments where you want to restrict which origins are accepted.
   *
   * If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.
   * Multiple origins can be provided as a comma-separated string (e.g. `https://app.example.com,https://myapp.vercel.app`).
   * If neither is provided, the SDK will infer it from the request host at runtime.
   */
  appBaseUrl?: string | string[];
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

  /**
   * Enable Enterprise Connect mode.
   *
   * Set to `true` when Auth0 acts as a pure SSO relay and your application owns
   * the session. `onCallback` must persist identity and return a `NextResponse`
   * with your session cookie. Session-backed methods (`getSession`, `getAccessToken`,
   * etc.) throw rather than returning `null`. Incompatible config (`offline_access`
   * scope, static `organization`) is reported at initialization.
   *
   * @see [Enterprise Connect](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#enterprise-connect-b2b-integration) for additional details
   */
  enterpriseConnect?: true;

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
   * Time limit, in milliseconds, for each HTTP request the SDK makes to Auth0 and to the APIs reached
   * through the Fetcher and the proxy. It applies to every individual request, not to a whole
   * operation.
   *
   * When not set, the SDK adds no limit and the underlying libraries keep their own: OIDC discovery
   * has 30 seconds, the logout token key fetch has 5 seconds, and the other requests have none.
   *
   * Must be an integer between 1 and 2147483647, otherwise an `InvalidConfigurationError` is thrown.
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
   * Number of seconds to refresh access tokens early when calling `getAccessToken`.
   * This is a server-side buffer applied to token expiration checks. For example,
   * with a buffer of 60 seconds, tokens expiring within the next minute will be
   * refreshed proactively when a refresh token is available.
   *
   * Defaults to `0` (no early refresh).
   */
  tokenRefreshBuffer?: number;

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

  // mTLS Configuration
  /**
   * Enable mTLS (Mutual TLS, RFC 8705) client authentication.
   *
   * When `true`, the SDK authenticates with Auth0 using a client TLS certificate
   * instead of a client secret or private-key JWT. Access tokens issued by Auth0
   * will be certificate-bound (`cnf.x5t#S256` claim), providing strong proof-of-possession
   * protection against token theft.
   *
   * Using mTLS requires:
   * 1. A TLS-aware `customFetch` implementation that attaches your client certificate
   *    (e.g. Node.js `undici` configured with `connect: { key, cert }`).
   * 2. The mTLS feature to be enabled on your Auth0 tenant.
   *
   * You do **not** need to provide `clientSecret` or `clientAssertionSigningKey`
   * when `useMtls` is `true` — the certificate is the sole client credential.
   *
   * Can also be enabled by setting the `AUTH0_MTLS=true` environment variable.
   *
   * @default false
   *
   * @example
   * ```typescript
   * import { Agent, fetch as undiciFetch } from "undici";
   * import { readFileSync } from "fs";
   *
   * const tlsAgent = new Agent({
   *   connect: {
   *     key: readFileSync("client.key"),
   *     cert: readFileSync("client.crt")
   *   }
   * });
   *
   * export const auth0 = new Auth0Client({
   *   useMtls: true,
   *   customFetch: (url, init) =>
   *     undiciFetch(url, { ...init, dispatcher: tlsAgent })
   * });
   * ```
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8705 | RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication}
   */
  useMtls?: boolean;

  /**
   * A custom `fetch` implementation used for all outbound requests to Auth0.
   *
   * Required when `useMtls` is `true` — provide a TLS-aware implementation that
   * attaches your client certificate to every request (e.g. `undici` with
   * `connect: { key, cert }`).
   *
   * Can also be used independently (without mTLS) to proxy requests, add custom
   * headers, or inject test doubles in unit tests.
   *
   * @example
   * ```typescript
   * import { Agent, fetch as undiciFetch } from "undici";
   *
   * const tlsAgent = new Agent({ connect: { cert, key } });
   *
   * export const auth0 = new Auth0Client({
   *   useMtls: true,
   *   customFetch: (url, init) =>
   *     undiciFetch(url, { ...init, dispatcher: tlsAgent })
   * });
   * ```
   */
  customFetch?: typeof fetch;

  /**
   * MFA context TTL in seconds. Controls how long encrypted mfa_token remains valid.
   * Default: 300 (5 minutes, matching Auth0's mfa_token expiration)
   *
   * Can also be set via AUTH0_MFA_TOKEN_TTL environment variable.
   *
   * @example
   * ```typescript
   * const auth0 = new Auth0Client({
   *   mfaTokenTtl: 600 // 10 minutes
   * });
   * ```
   */
  mfaTokenTtl?: number;

  /**
   * Content Security Policy nonce for inline scripts in popup flows.
   *
   * Required when your application uses CSP and the popup-based step-up
   * authentication flow (challengeMode: 'popup'). The nonce is
   * injected into the inline `<script>` tag of the postMessage HTML response.
   *
   * @example
   * ```typescript
   * const auth0 = new Auth0Client({
   *   cspNonce: crypto.randomUUID()
   * });
   * ```
   */
  cspNonce?: string;

  /**
   * Configuration for the OIDC discovery metadata cache.
   * Controls TTL and maximum cached issuers for MCD resolver mode.
   * Also applies in static mode (single cached entry).
   *
   * @see {@link DiscoveryCacheOptions}
   * @see [MCD Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#multiple-custom-domains-mcd)
   */
  discoveryCache?: DiscoveryCacheOptions;

  /**
   * Configuration for anonymous sessions (EA feature).
   * When enabled, allows pre-login identity with 1KB metadata.
   * Defaults to disabled; when disabled, routes are not mounted and methods return null.
   */
  anonymousSession?: AnonymousSessionConfig;
}

export type PagesRouterRequest = IncomingMessage | NextApiRequest;

export type PagesRouterResponse =
  ServerResponse<IncomingMessage> | NextApiResponse;
