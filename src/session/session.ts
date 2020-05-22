export interface ISession {
  /**
   * Any of the claims from the id_token.
   */
  readonly user: IClaims;

  /**
   * The id token.
   */
  readonly idToken?: string | undefined;

  /**
   * The access token.
   */
  readonly accessToken?: string | undefined;

  /**
   * Access token expiration timestamp, represented as the number of seconds since
   * the epoch (January 1, 1970 00:00:00 UTC).
   */
  readonly accessTokenExpiresAt?: number;

  /**
   * The access token scopes.
   */
  readonly accessTokenScope?: string | undefined;

  /**
   * The refresh token.
   */
  readonly refreshToken?: string | undefined;

  /**
   * The time on which the session was created.
   */
  readonly createdAt: number;
}

/**
 * Key-value store for the user's claims.
 */
export interface IClaims {
  [key: string]: any;
}

export default class Session implements ISession {
  user: IClaims;

  idToken?: string | undefined;

  accessToken?: string | undefined;

  accessTokenScope?: string | undefined;

  accessTokenExpiresAt?: number;

  refreshToken?: string | undefined;

  createdAt: number;

  constructor(user: IClaims, createdAt?: number) {
    this.user = user;

    if (createdAt) {
      this.createdAt = createdAt;
    } else {
      this.createdAt = Date.now();
    }
  }
}
