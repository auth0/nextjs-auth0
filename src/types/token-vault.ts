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
 * Response from Custom Token Exchange.
 */
export interface CustomTokenExchangeResponse {
  /** The access token issued by Auth0 */
  accessToken: string;
  /** The ID token, if openid scope was requested */
  idToken?: string;
  /** The refresh token, if offline_access scope was requested */
  refreshToken?: string;
  /** Token type, typically "Bearer" or "DPoP" */
  tokenType: string;
  /** Token lifetime in seconds */
  expiresIn: number;
  /** Granted scopes */
  scope?: string;
}
