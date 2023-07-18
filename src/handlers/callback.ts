import { IncomingMessage } from 'http';
import { strict as assert } from 'assert';
import { NextApiResponse, NextApiRequest } from 'next';
import { AuthorizationParameters, HandleCallback as BaseHandleCallback } from '../auth0-session';
import { Session } from '../session';
import { assertReqRes } from '../utils/assert';
import { NextConfig } from '../config';
import { CallbackHandlerError, HandlerErrorCause } from '../utils/errors';

/**
 * Use this function for validating additional claims on the user's ID token or adding removing items from
 * the session after login.
 *
 * @example Validate additional claims
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * const afterCallback = (req, res, session, state) => {
 *   if (session.user.isAdmin) {
 *     return session;
 *   } else {
 *     res.status(401).end('User is not admin');
 *   }
 * };
 *
 * export default handleAuth({
 *   async callback(req, res) {
 *     try {
 *       await handleCallback(req, res, { afterCallback });
 *     } catch (error) {
 *       res.status(error.status || 500).end();
 *     }
 *   }
 * });
 * ```
 *
 * @example Modify the session after login
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * const afterCallback = (req, res, session, state) => {
 *   session.user.customProperty = 'foo';
 *   delete session.refreshToken;
 *   return session;
 * };
 *
 * export default handleAuth({
 *   async callback(req, res) {
 *     try {
 *       await handleCallback(req, res, { afterCallback });
 *     } catch (error) {
 *       res.status(error.status || 500).end();
 *     }
 *   }
 * });
 * ```
 *
 * @example Redirect successful login based on claim
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * const afterCallback = (req, res, session, state) => {
 *   if (!session.user.isAdmin) {
 *     res.setHeader('Location', '/admin');
 *   }
 *   return session;
 * };
 *
 * export default handleAuth({
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
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type AfterCallback = (
  req: NextApiRequest,
  res: NextApiResponse,
  session: Session,
  state?: { [key: string]: any }
) => Promise<Session | undefined> | Session | undefined;

/**
 * Options to customize the callback handler.
 *
 * @see {@link HandleCallback}
 *
 * @category Server
 */
export interface CallbackOptions {
  afterCallback?: AfterCallback;

  /**
   * This is useful to specify in addition to {@link BaseConfig.baseURL} when your app runs on multiple domains,
   * it should match {@link LoginOptions.authorizationParams.redirect_uri}.
   */
  redirectUri?: string;

  /**
   * This is useful to specify instead of {@link NextConfig.organization} when your app has multiple
   * organizations, it should match {@link LoginOptions.authorizationParams}.
   */
  organization?: string;

  /**
   * This is useful for sending custom query parameters in the body of the code exchange request
   * for use in Actions/Rules.
   */
  authorizationParams?: Partial<AuthorizationParameters>;
}

/**
 * Options provider for the default callback handler.
 * Use this to generate options that depend on values from the request.
 *
 * @category Server
 */
export type CallbackOptionsProvider = (req: NextApiRequest) => CallbackOptions;

/**
 * Use this to customize the default callback handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   callback: handleCallback({ redirectUri: 'https://example.com' })
 * });
 * ```
 *
 * @example Pass a function that receives the request and returns an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   callback: handleCallback((req) => {
 *     return { redirectUri: 'https://example.com' };
 *   })
 * });
 * ```
 *
 * This is useful for generating options that depend on values from the request.
 *
 * @example Override the callback handler
 *
 * ```js
 * import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   callback: async (req, res) => {
 *     try {
 *       await handleCallback(req, res, {
 *         redirectUri: 'https://example.com'
 *       });
 *     } catch (error) {
 *       console.error(error);
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type HandleCallback = {
  (req: NextApiRequest, res: NextApiResponse, options?: CallbackOptions): Promise<void>;
  (provider: CallbackOptionsProvider): CallbackHandler;
  (options: CallbackOptions): CallbackHandler;
};

/**
 * The handler for the `/api/auth/callback` API route.
 *
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type CallbackHandler = (req: NextApiRequest, res: NextApiResponse, options?: CallbackOptions) => Promise<void>;

/**
 * @ignore
 */
const idTokenValidator =
  (afterCallback?: AfterCallback, organization?: string): AfterCallback =>
  (req, res, session, state) => {
    if (organization) {
      if (organization.startsWith('org_')) {
        assert(session.user.org_id, 'Organization Id (org_id) claim must be a string present in the ID token');
        assert.equal(
          session.user.org_id,
          organization,
          `Organization Id (org_id) claim value mismatch in the ID token; ` +
            `expected "${organization}", found "${session.user.org_id}"`
        );
      } else {
        assert(session.user.org_name, 'Organization Name (org_name) claim must be a string present in the ID token');
        assert.equal(
          session.user.org_name,
          organization.toLowerCase(),
          `Organization Name (org_name) claim value mismatch in the ID token; ` +
            `expected "${organization}", found "${session.user.org_name}"`
        );
      }
    }
    if (afterCallback) {
      return afterCallback(req, res, session, state);
    }
    return session;
  };

/**
 * @ignore
 */
export default function handleCallbackFactory(handler: BaseHandleCallback, config: NextConfig): HandleCallback {
  const callback: CallbackHandler = async (req: NextApiRequest, res: NextApiResponse, options = {}): Promise<void> => {
    try {
      assertReqRes(req, res);
      return await handler(req, res, {
        ...options,
        afterCallback: idTokenValidator(options.afterCallback, options.organization || config.organization)
      });
    } catch (e) {
      throw new CallbackHandlerError(e as HandlerErrorCause);
    }
  };
  return (
    reqOrOptions: NextApiRequest | CallbackOptionsProvider | CallbackOptions,
    res?: NextApiResponse,
    options?: CallbackOptions
  ): any => {
    if (reqOrOptions instanceof IncomingMessage && res) {
      return callback(reqOrOptions, res, options);
    }
    if (typeof reqOrOptions === 'function') {
      return (req: NextApiRequest, res: NextApiResponse) => callback(req, res, reqOrOptions(req));
    }
    return (req: NextApiRequest, res: NextApiResponse) => callback(req, res, reqOrOptions as CallbackOptions);
  };
}
