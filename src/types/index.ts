export interface TokenSet {
  accessToken: string;
  idToken?: string;
  scope?: string;
  requestedScope?: string;
  refreshToken?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  audience?: string;
  token_type?: string; // the type of the access token (e.g., "Bearer", "DPoP")
}

export interface ConnectionTokenSet {
  accessToken: string;
  scope?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  connection: string;
  [key: string]: unknown;
}

export interface AccessTokenSet {
  accessToken: string;
  scope?: string;
  requestedScope?: string;
  audience: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
  token_type?: string; // the type of the access token (e.g., "Bearer", "DPoP")
}

export interface SessionData {
  user: User;
  tokenSet: TokenSet;
  accessTokens?: AccessTokenSet[];
  internal: {
    // the session ID from the authorization server
    sid: string;
    // the time at which the session was created in seconds since epoch
    createdAt: number;
  };
  connectionTokenSets?: ConnectionTokenSet[];
  [key: string]: unknown;
}

export interface SessionDataStore {
  /**
   * Gets the session from the store given a session ID.
   */
  get(id: string): Promise<SessionData | null>;

  /**
   * Upsert a session in the store given a session ID and `SessionData`.
   */
  set(id: string, session: SessionData): Promise<void>;

  /**
   * Destroys the session with the given session ID.
   */
  delete(id: string): Promise<void>;

  /**
   * Deletes the session with the given logout token which may contain a session ID or a user ID, or both.
   */
  deleteByLogoutToken?(logoutToken: LogoutToken): Promise<void>;
}

export type LogoutToken = { sub?: string; sid?: string };

export interface User {
  sub: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  /**
   * The organization ID that the user belongs to.
   * This field is populated when the user logs in through an organization.
   */
  org_id?: string;

  [key: string]: any;
}

export type {
  Auth0ClientOptions,
  PagesRouterRequest,
  PagesRouterResponse
} from "../server/client.js";

export type {
  BeforeSessionSavedHook,
  OnCallbackHook,
  RoutesOptions,
  AuthClientOptions,
  OnCallbackContext,
  Routes
} from "../server/auth-client.js";

export type { TransactionCookieOptions } from "../server/transaction-store.js";

export type {
  SessionConfiguration,
  SessionCookieOptions,
  SessionStoreOptions
} from "../server/session/abstract-session-store.js";

export type {
  CookieOptions,
  ReadonlyRequestCookies
} from "../server/cookies.js";

export type {
  TransactionStoreOptions,
  TransactionState
} from "../server/transaction-store.js";

export interface StartInteractiveLoginOptions {
  /**
   * Authorization parameters to be passed to the authorization server.
   */
  authorizationParameters?: AuthorizationParameters;
  /**
   * The URL to redirect to after a successful login.
   */
  returnTo?: string;
}

export interface AuthorizationParameters {
  /**
   * The scope of the access request, expressed as a list of space-delimited, case-sensitive strings.
   * Defaults to `"openid profile email offline_access"`.
   */
  scope?: string | null | { [key: string]: string };
  /**
   * The unique identifier of the target API you want to access.
   */
  audience?: string | null;
  /**
   * The URL to which the authorization server will redirect the user after granting authorization.
   */
  redirect_uri?: string | null;
  /**
   * The maximum amount of time, in seconds, after which a user must reauthenticate.
   */
  max_age?: number;
  /**
   * The unique identifier of the organization that the user should be logged into.
   * When specified, the user will be prompted to log in to this specific organization.
   * The organization ID will be included in the user's session after successful authentication.
   */
  organization?: string;
  /**
   * Additional authorization parameters.
   */
  [key: string]: unknown;
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

/**
 * Logout strategy options for controlling logout endpoint selection.
 */
export type LogoutStrategy = "auto" | "oidc" | "v2";

export interface BackchannelAuthenticationOptions {
  /**
   * Human-readable message to be displayed at the consumption device and authentication device.
   * This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
   */
  bindingMessage: string;
  /**
   * The login hint to inform which user to use.
   */
  loginHint: {
    /**
     * The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.
     */
    sub: string;
  };
  /**
   * Set a custom expiry time for the CIBA flow in seconds. Defaults to 300 seconds (5 minutes) if not set.
   */
  requestedExpiry?: number;
  /**
   * Optional authorization details to use Rich Authorization Requests (RAR).
   * @see https://auth0.com/docs/get-started/apis/configure-rich-authorization-requests
   */
  authorizationDetails?: AuthorizationDetails[];
  /**
   * Authorization Parameters to be sent with the authorization request.
   */
  authorizationParams?: AuthorizationParameters;
}

export interface BackchannelAuthenticationResponse {
  tokenSet: TokenSet;
  idTokenClaims?: { [key: string]: any };
  authorizationDetails?: AuthorizationDetails[];
}

export interface AuthorizationDetails {
  readonly type: string;
  readonly [parameter: string]: unknown;
}

export type GetAccessTokenOptions = {
  refresh?: boolean | null;
  scope?: string | null;
  /**
   * Please note: If you are passing audience, ensure that the used audiences and scopes are
   * part of the Application's Refresh Token Policies in Auth0 when configuring Multi-Resource Refresh Tokens (MRRT).
   * {@link https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token|See Auth0 Documentation on Multi-resource Refresh Tokens}
   */
  audience?: string | null;
};
