export default interface OidcClientSettings {
  /**
   * Timeout (in milliseconds) for HTTP requests to Auth0.
   */
  httpTimeout?: number;

  /**
   * Allowed leeway for id_tokens (in milliseconds).
   */
  clockTolerance?: number;
}
