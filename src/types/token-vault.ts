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
