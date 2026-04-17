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
   * The name of the Auth0 connection to use for authentication.
   *
   * Use this to skip the Universal Login page and go directly to a specific
   * identity provider or authentication method (e.g. `'google-oauth2'`, `'github'`, `'email'`, `'sms'`).
   */
  connection?: string;
  /**
   * Hint to the Auth0 Universal Login page which screen to show.
   *
   * - `'login'` — show the login screen (default)
   * - `'signup'` — show the sign-up / registration screen
   */
  screen_hint?: "login" | "signup";
  /**
   * Pre-fills the email or phone field on the Universal Login page.
   *
   * Pass the user's known identifier (email address or phone number) to
   * improve UX by skipping manual entry.
   */
  login_hint?: string;
  /**
   * Additional authorization parameters.
   */
  [key: string]: unknown;
}
