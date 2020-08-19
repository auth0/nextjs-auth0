import { NextApiRequest, NextApiResponse } from 'next';
import { IncomingMessage } from 'http';
import { ISession } from './session/session';
import { LoginOptions } from './handlers/login';
import { ITokenCache } from './tokens/token-cache';
import { CallbackOptions } from './handlers/callback';
import { ProfileOptions } from './handlers/profile';
import { LogoutOptions } from './handlers/logout';
import { IApiRoute } from './handlers/require-authentication';

export interface ISignInWithAuth0 {
  /**
   * Login handler which will redirect the user to Auth0.
   */
  handleLogin: (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions) => Promise<void>;

  /**
   * Callback handler which will complete the transaction and create a local session.
   */
  handleCallback: (req: NextApiRequest, res: NextApiResponse, options?: CallbackOptions) => Promise<void>;

  /**
   * Logout handler which will clear the local session and the Auth0 session.
   */
  handleLogout: (req: NextApiRequest, res: NextApiResponse, options?: LogoutOptions) => Promise<void>;

  /**
   * Profile handler which return profile information about the user.
   */
  handleProfile: (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void>;

  /**
   * Session handler which returns the current session
   */
  getSession: (req: IncomingMessage) => Promise<ISession | null | undefined>;

  /**
   * Handle to require authentication for an API route.
   */
  requireAuthentication: (apiRoute: IApiRoute) => IApiRoute;

  /**
   * Token cache which allows you to get an access token for the current user.
   */
  tokenCache: (req: NextApiRequest, res: NextApiResponse) => ITokenCache;
}
