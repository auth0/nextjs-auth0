import OidcClientSettings from './oidc-client-settings';
import { ICookieSessionStoreSettings } from './session/cookie-store/settings';

export default interface IAuth0Settings {
  /**
   * Auth0 domain.
   */
  domain: string;

  /**
   * Auth0 client ID.
   */
  clientId: string;

  /**
   * Auth0 client secret.
   */
  clientSecret?: string;

  /**
   * Url to redirect to after the user has signed in.
   */
  redirectUri: string;

  /**
   * URL to redirect to after the user has signed out.
   */
  postLogoutRedirectUri: string;

  /**
   * The scope requested by the client.
   */
  scope: string;

  /**
   * API Audience.
   */
  audience?: string;

  /**
   * Settings related to the session.
   */
  session?: ICookieSessionStoreSettings;

  /**
   * Settings for the OIDC Client which performs the code exchange.
   */
  oidcClient?: OidcClientSettings;
}
