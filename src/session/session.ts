export interface ISession {
  /**
   * Any of the custom clails from the token.
   */
  readonly [key: string]: string | undefined;

  /**
   * The id token.
   */
  readonly idToken?: string | undefined;

  /**
   * The access token.
   */
  readonly accessToken?: string | undefined;
}
