import { AuthorizationParameters } from "./authorize.js";

/**
 * Options to initiate a connect account flow using the My Account API.
 * @see https://auth0.com/docs/manage-users/my-account-api
 */
export interface ConnectAccountOptions {
  /**
   * The name of the connection to link the account with (e.g., 'google-oauth2', 'facebook').
   */
  connection: string;
  /**
   * Authorization parameters to be passed to the authorization server.
   */
  authorizationParams?: AuthorizationParameters;
  /**
   * The URL to redirect to after successfully connecting the account.
   */
  returnTo?: string;
}

export enum RESPONSE_TYPES {
  /**
   * Authorization Code flow.
   */
  CODE = "code",
  /**
   * Connect Account flow.
   */
  CONNECT_CODE = "connect_code"
}

export interface ConnectAccountRequest {
  /**
   * The access token with the `create:me:connected_accounts` scope.
   */
  accessToken: string;
  /**
   * The name of the connection to link the account with (e.g., 'google-oauth2', 'facebook').
   */
  connection: string;
  /**
   * The URI to redirect to after the connection process completes.
   */
  redirectUri: string;
  /**
   * An opaque value used to maintain state between the request and callback.
   */
  state?: string;
  /**
   * The PKCE code challenge derived from the code verifier.
   */
  codeChallenge?: string;
  /**
   * The method used to derive the code challenge. Required when code_challenge is provided.
   */
  codeChallengeMethod?: string;
  /**
   * Authorization parameters to be sent to the underlying Identity Provider (IdP)
   */
  authorizationParams?: AuthorizationParameters;
}

export interface ConnectAccountResponse {
  /**
   * The URI to redirect the user to for connecting their account.
   */
  connectUri: string;
  /**
   * Parameters required for the connection process, including a ticket.
   */
  connectParams: {
    ticket: string;
  };
  /**
   * The authentication session identifier.
   */
  authSession: string;
  /**
   * The lifetime in seconds of the connect account session.
   */
  expiresIn: number;
}

export interface CompleteConnectAccountRequest {
  accessToken: string;
  /**
   * The authentication session identifier.
   */
  authSession: string;
  /**
   * The authorization code returned from the connect flow.
   */
  connectCode: string;
  /**
   * The redirect URI used in the original request.
   */
  redirectUri: string;
  /**
   * The PKCE code verifier.
   */
  codeVerifier?: string;
}

export interface CompleteConnectAccountResponse {
  /**
   * The unique identifier of the connected account.
   */
  id: string;
  /**
   * The name of the connection associated with the connected account.
   */
  connection: string;
  /**
   * The access type, always 'offline'.
   */
  accessType: string;
  /**
   * Array of scopes granted.
   */
  scopes: string[];
  /**
   * ISO date string of when the connected account was created.
   */
  createdAt: string;
  /**
   * ISO date string of when the refresh token expires (optional).
   */
  expiresAt?: string;
}
