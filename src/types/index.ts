export interface TokenSet {
  accessToken: string;
  scope?: string;
  refreshToken?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
}

export interface FederatedConnectionTokenSet {
  accessToken: string
  scope?: string
  expiresAt: number // the time at which the access token expires in seconds since epoch
  connection: string
  [key: string]: unknown
}

export interface SessionData {
  user: User;
  tokenSet: TokenSet;
  internal: {
    // the session ID from the authorization server
    sid: string;
    // the time at which the session was created in seconds since epoch
    createdAt: number;
  }
  federatedConnectionTokenSets?: FederatedConnectionTokenSet[];
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
  org_id?: string;

  [key: string]: any;
}

export type {
  Auth0ClientOptions,
  PagesRouterRequest,
  PagesRouterResponse
} from "../server/client";

export type {
  AuthorizationParameters,
  BeforeSessionSavedHook,
  OnCallbackHook,
  RoutesOptions,
  AuthClientOptions,
  OnCallbackContext,
  Routes
} from "../server/auth-client";

export type { TransactionCookieOptions } from "../server/transaction-store";

export type {
  SessionConfiguration,
  SessionCookieOptions,
  SessionStoreOptions
} from "../server/session/abstract-session-store";

export type { CookieOptions, ReadonlyRequestCookies } from "../server/cookies";

export type {
  TransactionStoreOptions,
  TransactionState
} from "../server/transaction-store";
