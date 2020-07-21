export interface AccessTokenRequest {
  scopes?: Array<string>;
  refresh?: boolean;
}

export interface AccessTokenResponse {
  /**
   * Access token returned from the token cache.
   */
  accessToken?: string | undefined;
}

export interface ITokenCache {
  /**
   * Get a user's access token.
   */
  getAccessToken(accessTokenRequest?: AccessTokenRequest): Promise<AccessTokenResponse>;
}
