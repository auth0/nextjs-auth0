import { GetSession, GetAccessToken } from './session';
import { WithApiAuthRequired, WithSSRAuthRequired } from './helpers';
import { HandleAuth, HandleCallback, HandleLogin, HandleLogout, HandleProfile } from './handlers';
import { ConfigParameters } from './auth0-session';

export interface SignInWithAuth0 {
  /**
   * Session getter
   */
  getSession: GetSession;

  /**
   * Access Token getter
   */
  getAccessToken: GetAccessToken;

  /**
   * Login handler which will redirect the user to Auth0.
   */
  handleLogin: HandleLogin;

  /**
   * Callback handler which will complete the transaction and create a local session.
   */
  handleCallback: HandleCallback;

  /**
   * Logout handler which will clear the local session and the Auth0 session.
   */
  handleLogout: HandleLogout;

  /**
   * Profile handler which return profile information about the user.
   */
  handleProfile: HandleProfile;

  /**
   * Helper that adds auth to an API Route
   */
  withApiAuthRequired: WithApiAuthRequired;

  /**
   * Helper that adds auth to an SSR Page Route
   */
  withSSRAuthRequired: WithSSRAuthRequired;

  /**
   * Create the main handlers for your api routes
   */
  handleAuth: HandleAuth;
}

export type InitAuth0 = (params?: ConfigParameters) => SignInWithAuth0;
