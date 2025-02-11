export interface TokenSet {
  accessToken: string;
  scope?: string;
  refreshToken?: string;
  expiresAt: number; // the time at which the access token expires in seconds since epoch
}

export interface SessionData {
  user: User;
  tokenSet: TokenSet;
  internal: {
    // the session ID from the authorization server
    sid: string;
    // the time at which the session was created in seconds since epoch
    createdAt: number;
  };
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
