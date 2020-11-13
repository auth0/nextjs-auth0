import { NextApiRequest, NextApiResponse } from 'next';
import { ProfileOptions, HandleLogin, HandleLogout, HandleCallback } from './handlers';
import { GetSession, GetAccessToken } from './session';
import { WithApiAuth, WithPageAuth } from './helpers';

export interface SignInWithAuth0 {
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
  handleProfile: (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void>;

  /**
   * Session getter
   */
  getSession: GetSession;

  /**
   * Access Token getter
   */
  getAccessToken: GetAccessToken;

  /**
   * Helper that adds auth to an API Route
   */
  withApiAuth: WithApiAuth;

  /**
   * Helper that adds auth to an SSR Page Route
   */
  withPageAuth: WithPageAuth;
}
