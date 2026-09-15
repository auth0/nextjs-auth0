export interface StartInteractiveLoginOptions {
  /**
   * Authorization parameters to be passed to the authorization server.
   */
  authorizationParameters?: AuthorizationParameters;
  /**
   * The URL to redirect to after a successful login.
   */
  returnTo?: string;
  /**
   * Control callback return behavior.
   * - 'redirect' (default): Standard OAuth redirect to returnTo
   * - 'popup': Return HTML with postMessage for popup flows
   */
  challengeMode?: "redirect" | "popup";
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
   * - `'reset-password'` — show the password reset screen (New Universal Login only)
   *
   * Auth0 may accept additional custom screen names; use `string & {}` to pass
   * arbitrary values while retaining autocomplete for the known literals.
   */
  screen_hint?: "login" | "signup" | "reset-password" | (string & {});
  /**
   * Pre-fills the email or phone field on the Universal Login page.
   *
   * Pass the user's known identifier (email address or phone number) to
   * improve UX by skipping manual entry.
   */
  login_hint?: string;
  /**
   * Controls whether the authorization server prompts the user for reauthentication
   * or consent.
   *
   * - `'none'` — no UI shown; fails with `login_required` if interaction is needed
   * - `'login'` — force reauthentication even if a session exists
   * - `'consent'` — force consent prompt even if previously granted
   * - `'select_account'` — prompt user to select an account
   * - `'create'` — prompt user to create a new account (Auth0 New Universal Login)
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
   */
  prompt?:
    "none" | "login" | "consent" | "select_account" | "create" | (string & {});
  /**
   * Requested Authentication Context Class Reference values.
   * Space-separated string indicating the authentication context the authorization
   * server should satisfy (e.g. step-up MFA policies).
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
   */
  acr_values?: string;
  /**
   * End-user's preferred languages for the UI, as a space-separated list of
   * BCP 47 language tags in order of preference (e.g. `'fr-CA fr en'`).
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
   */
  ui_locales?: string;
  /**
   * Controls how the authorization server displays the authentication UI.
   *
   * - `'page'` — full page redirect (default)
   * - `'popup'` — popup window
   * - `'touch'` — touch-optimized UI
   * - `'wap'` — WAP browser UI
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
   */
  display?: "page" | "popup" | "touch" | "wap" | (string & {});
  /**
   * Forces a specific Experiment Center variant for this login instead of
   * letting Auth0 assign one server-side. Use together with `variation_id`.
   *
   * Pass this per-login (as a query param on `/auth/login` or via
   * `startInteractiveLogin`) rather than at client construction time. Setting
   * it on the client applies the override to every login the SDK starts, which
   * defeats the A/B test by pinning all users to the same variant.
   *
   * **Testing:** drive from test automation (e.g. Cypress/Playwright) with IDs
   * from a CI environment variable against a staging tenant. Do not hard-code
   * this in shipped app code.
   *
   * **Production:** pass the variant decision from a feature-flag tool
   * (e.g. LaunchDarkly) that has already decided which variant the user should
   * see for this login.
   *
   * @see https://auth0.com/docs/customize/experiment-center/overview
   */
  experiment_id?: string;

  /**
   * The variation to force within the experiment identified by `experiment_id`.
   * Auth0 uses this value instead of computing an assignment for the current
   * login. The override applies to this login only; the next login without
   * these params reverts to normal server-side assignment.
   */
  variation_id?: string;

  /**
   * Identifies the audience segment the forced variant belongs to, for
   * experiments that target different variations to different segments.
   *
   * `variation_id` selects the variation; `segment_id` tells Auth0 which
   * segment that variation was defined under so the correct one is applied.
   * Only pass this for segment-targeted experiments -- for a non-segmented
   * experiment, `experiment_id` and `variation_id` alone are sufficient.
   */
  segment_id?: string;

  /**
   * Additional authorization parameters.
   */
  [key: string]: unknown;
}
