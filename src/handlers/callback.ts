import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory, Config, callbackHandler, TransientStore } from '../auth0-session';
import { Session, SessionCache } from '../session';
import { assertReqRes } from '../utils/assert';

/**
 * Use this function for validating additional claims on the user's access token or adding removing items from
 * the session after login, eg
 *
 * ### Validate additional claims
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * const afterCallback = (req, res, session, state) => {
 *   if (!session.user.isAdmin) {
 *     throw new UnauthorizedError('User is not admin');
 *   }
 *   return session;
 * };
 *
 * export handleAuth({
 *   async callback(req, res) {
 *     try {
 *       await handleCallback(req, res, { afterCallback });
 *     } catch (error) {
 *       res.status(error.status || 500).end(error.message);
 *     }
 *   }
 * });
 * ```
 *
 * ### Modify the session after login
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * const afterCallback = (req, res, session, state) => {
 *   session.user.customProperty = 'foo';
 *   delete session.refreshToken;
 *   return session;
 * };
 *
 * export handleAuth({
 *   async callback(req, res) {
 *     try {
 *       await handleCallback(req, res, { afterCallback });
 *     } catch (error) {
 *       res.status(error.status || 500).end(error.message);
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type AfterCallback = (
  req: NextApiRequest,
  res: NextApiResponse,
  session: Session,
  state: { [key: string]: any }
) => Promise<Session> | Session;

/**
 * Options to customise the callback handler.
 *
 * @category Server
 */
export type CallbackOptions = {
  afterCallback?: AfterCallback;
};

/**
 * The handler for the `api/auth/callback` route.
 *
 * @category Server
 */
export type HandleCallback = (req: NextApiRequest, res: NextApiResponse, options?: CallbackOptions) => Promise<void>;

/**
 * @ignore
 */
export default function handleLoginFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache,
  transientHandler: TransientStore
): HandleCallback {
  const handler = callbackHandler(config, getClient, sessionCache, transientHandler);
  return async (req, res, options): Promise<void> => {
    assertReqRes(req, res);
    return handler(req, res, options);
  };
}
