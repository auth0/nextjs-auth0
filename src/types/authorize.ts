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
