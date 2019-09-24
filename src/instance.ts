import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';

import { ISession } from './session/session';
import { CallbackOptions } from './handlers/callback-options';

export interface ISignInWithAuth0 {
  /**
   * Login handler which will redirect the user to Auth0.
   */
  handleLogin: (req: IncomingMessage, res: ServerResponse) => Promise<void>;

  /**
   * Callback handler which will complete the transaction and create a local session.
   */
  handleCallback: (req: IncomingMessage, res: ServerResponse, options: CallbackOptions) => Promise<void>;

  /**
   * Logout handler which will clear the local session and the Auth0 session
   */
  handleLogout: (req: IncomingMessage, res: ServerResponse) => Promise<void>;

  /**
   * Profile handler which return profile information about the user.
   */
  handleProfile: (req: NextApiRequest, res: NextApiResponse) => Promise<void>;

  /**
   * Profile handler which return profile information about the user.
   */
  getSession: (req: IncomingMessage) => Promise<ISession | null | undefined>;
}
