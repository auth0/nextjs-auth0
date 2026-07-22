/**
 * Token type URNs for Custom Token Exchange and Session Transfer flows (RFC 8693).
 */
export enum TOKEN_TYPES {
  /**
   * OAuth 2.0 ID token.
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-3-3.6 RFC 8693 Section 3-3.6}
   */
  ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token",

  /**
   * OAuth 2.0 access token.
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-3-3.2 RFC 8693 Section 3-3.2}
   */
  ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token",

  /**
   * Session Transfer Token issued by Auth0 (Phase 2 CTE).
   * When `issued_token_type` equals this value, the `access_token` in the response
   * is a one-shot STT — not a usable API bearer token. Pass it to
   * `buildSessionTransferRedirect` to start the impersonation redirect.
   */
  SESSION_TRANSFER_TOKEN = "urn:auth0:params:oauth:token-type:session_transfer_token"
}

export enum SUBJECT_TOKEN_TYPES {
  /**
   * Indicates that the token is an OAuth 2.0 refresh token issued by the given authorization server.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-3-3.4 RFC 8693 Section 3-3.4}
   */
  SUBJECT_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token",

  /**
   * Indicates that the token is an OAuth 2.0 access token issued by the given authorization server.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-3-3.2 RFC 8693 Section 3-3.2}
   */
  SUBJECT_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
}

/**
 * Options for retrieving a connection access token.
 */
export interface AccessTokenForConnectionOptions {
  /**
   * The connection name for while you want to retrieve the access token.
   */
  connection: string;

  /**
   * An optional login hint to pass to the authorization server.
   */
  login_hint?: string;

  /**
   * The type of token that is being exchanged.
   *
   * Uses the {@link SUBJECT_TOKEN_TYPES} enum with the following allowed values:
   * - `SUBJECT_TYPE_REFRESH_TOKEN`: `"urn:ietf:params:oauth:token-type:refresh_token"`
   * - `SUBJECT_TYPE_ACCESS_TOKEN`: `"urn:ietf:params:oauth:token-type:access_token"`
   *
   * Defaults to `SUBJECT_TYPE_REFRESH_TOKEN`.
   */
  subject_token_type?: SUBJECT_TOKEN_TYPES;
}

export interface ConnectionTokenSet {
  accessToken: string;
  scope?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  connection: string;
  [key: string]: unknown;
}

/**
 * Grant type for Custom Token Exchange as per RFC 8693.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8693 RFC 8693}
 */
export const GRANT_TYPE_CUSTOM_TOKEN_EXCHANGE =
  "urn:ietf:params:oauth:grant-type:token-exchange";

/**
 * Options for Custom Token Exchange.
 *
 * Custom Token Exchange allows exchanging external tokens for Auth0 tokens
 * without a browser redirect. The external token is validated by an Auth0 Action
 * with the Custom Token Exchange trigger.
 *
 * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Auth0 Custom Token Exchange Documentation}
 */
export interface CustomTokenExchangeOptions {
  /**
   * The external token being exchanged.
   * This will be validated by your Auth0 Action with the Custom Token Exchange trigger.
   *
   * **Validation**: Must be a non-empty string.
   */
  subjectToken: string;

  /**
   * Custom URI identifying the token type.
   *
   * **Validation Rules**:
   * - Must be 10-100 characters
   * - Must be a valid URI (URL or URN format)
   *
   * Note: Reserved namespaces are validated by Auth0 when creating CTE profiles.
   *
   * @example 'urn:acme:legacy-token'
   * @example 'https://mycompany.com/token-type/v1'
   */
  subjectTokenType: string;

  /**
   * The unique identifier of the target API.
   */
  audience?: string;

  /**
   * Space-delimited OAuth 2.0 scopes.
   *
   * **Note**: These scopes are merged with SDK default scopes
   * (openid profile email offline_access). Duplicates are removed.
   */
  scope?: string;

  /**
   * Organization ID or name for multi-tenant scenarios.
   * The organization ID will be present in the resulting access token claims.
   */
  organization?: string;

  /**
   * Actor token for delegation/impersonation scenarios (RFC 8693).
   * Represents the identity of the acting party.
   *
   * If provided, `actorTokenType` is required.
   */
  actorToken?: string;

  /**
   * Actor token type URI (required if actorToken is provided).
   */
  actorTokenType?: string;

  /**
   * Additional custom parameters passed to the token endpoint.
   * Accessible in Auth0 Action via `event.request.body`.
   *
   * Use this for custom parameters instead of index signature to avoid TypeScript issues.
   */
  additionalParameters?: Record<string, unknown>;
}

/**
 * Represents the `act` (actor) claim from an ID token issued via RFC 8693 delegation.
 * The `act` claim identifies the acting party and may be nested to represent a delegation chain.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8693#section-4.1 RFC 8693 §4.1}
 */
export interface ActClaim {
  /** The subject identifier of the acting party. */
  sub: string;
  /** Nested actor claim representing a delegation chain. */
  act?: ActClaim;
  [key: string]: unknown;
}

/**
 * Options for requesting a Session Transfer Token (STT).
 *
 * The SDK fills in `audience`, `grant_type`, `actor_token`, and `actor_token_type`
 * automatically. You supply `subjectToken` and `subjectTokenType` — your own proof
 * of which customer to impersonate, validated by your Action.
 */
export interface SessionTransferTokenOptions {
  /**
   * Your proof of which customer to impersonate.
   * Opaque to Auth0 — validated only by your CTE Action via `setUserById`.
   * The SDK never produces this value.
   */
  subjectToken: string;

  /**
   * Your CTE Profile ID that routes the exchange to your Action.
   * Same validation rules as `CustomTokenExchangeOptions.subjectTokenType` (10–100 chars, valid URI).
   */
  subjectTokenType: string;

  /**
   * Reason for impersonation. Forwarded to the token endpoint as a body param
   * and readable by your Action at `event.request.body.reason`.
   * Must be included in `setActor(...)` by your Action for it to appear as `act.reason`.
   */
  reason?: string;

  /**
   * Organization ID or name. Forwarded to `/authorize` by `buildSessionTransferRedirect`.
   * Required when the STT is issued in an org context.
   */
  organization?: string;

  /**
   * Scopes for the impersonation session tokens.
   * Merged with SDK default scopes (openid, profile, email).
   * Note: `offline_access` is silently suppressed by Auth0 for impersonation sessions.
   */
  scope?: string;

  /**
   * Explicit actor override. Omit to use the agent session's ID token.
   * If the session ID token is expired but a refresh token is available the SDK refreshes it first.
   * Fails with `ACTOR_UNAVAILABLE` only when no usable token can be resolved. If that refresh
   * itself requires MFA step-up, an `MfaRequiredError` is thrown instead.
   * Precedence: explicit `actor` → session ID token (refreshed if stale) → throws `ACTOR_UNAVAILABLE`.
   */
  actor?: {
    token: string;
    type: TOKEN_TYPES | string;
  };

  /**
   * Additional custom parameters forwarded to the token endpoint.
   * Accessible in your Action via `event.request.body`.
   */
  additionalParameters?: Record<string, unknown>;
}

/**
 * Result from `requestSessionTransferToken`.
 *
 * Branch on `issuedTokenType`, never `tokenType`.
 * The `sessionTransferToken` is one-shot (~60s) — pass it directly to
 * `buildSessionTransferRedirect`. Never cache or store it.
 */
export interface SessionTransferTokenResult {
  /** The Session Transfer Token. One-shot, ~60s. Pass to `buildSessionTransferRedirect`. */
  sessionTransferToken: string;
  /** Always `TOKEN_TYPES.SESSION_TRANSFER_TOKEN`. Branch on this, not `tokenType`. */
  issuedTokenType: TOKEN_TYPES.SESSION_TRANSFER_TOKEN | string;
  /** Token lifetime in seconds as reported by the server. Undefined when the server omits it. */
  expiresIn?: number;
  /** `"N_A"` — informational only. Never branch on this. */
  tokenType?: string;
}

/**
 * Response from Custom Token Exchange.
 */
export interface CustomTokenExchangeResponse {
  /** The access token issued by Auth0 */
  accessToken: string;
  /** The ID token, if openid scope was requested */
  idToken?: string;
  /**
   * The refresh token, if offline_access scope was requested.
   * Note: Auth0 suppresses the refresh token when `actor_token` is present in the request.
   * This field will be undefined in delegation/impersonation flows.
   */
  refreshToken?: string;
  /** Token type, typically "Bearer" or "DPoP" */
  tokenType: string;
  /** Token lifetime in seconds */
  expiresIn: number;
  /** Granted scopes */
  scope?: string;
  /**
   * The actor claim decoded from the ID token, present in delegation/impersonation flows (RFC 8693 §4.1).
   * Represents the acting party. May be nested to reflect a delegation chain.
   */
  act?: ActClaim;
}
