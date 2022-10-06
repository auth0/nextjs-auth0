import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import { HandleLogin } from './login';
import { HandleLogout } from './logout';
import { HandleCallback } from './callback';
import { HandleProfile } from './profile';
import { HandlerError } from '../utils/errors';

/**
 * If you want to add some custom behavior to the default auth handlers, you can pass in custom handlers for
 * `login`, `logout`, `callback`, and `profile`. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 * import { errorReporter, logger } from '../../../utils';
 *
 * export default handleAuth({
 *   async login(req, res) {
 *     try {
 *        // Pass in custom params to your handler
 *       await handleLogin(req, res, { authorizationParams: { customParam: 'foo' } });
 *       // Add your own custom logging.
 *       logger('Redirecting to login');
 *     } catch (error) {
 *       // Add you own custom error logging.
 *       errorReporter(error);
 *       res.status(error.status || 500).end();
 *     }
 *   }
 * });
 * ```
 *
 * Alternatively, you can customize the default handlers without overriding them. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   login: handleLogin({
 *     authorizationParams: { customParam: 'foo' } // Pass in custom params
 *   })
 * });
 * ```
 *
 * You can also create new handlers by customizing the default ones. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   signup: handleLogin({
 *     authorizationParams: { screen_hint: 'signup' }
 *   })
 * });
 * ```
 *
 * @category Server
 */
export type Handlers = ApiHandlers | ErrorHandlers;

type ApiHandlers = {
  [key: string]: NextApiHandler;
};

type ErrorHandlers = {
  onError?: OnError;
};

/**
 * The main way to use the server SDK.
 *
 * Simply set the environment variables per {@link ConfigParameters} then create the file
 * `pages/api/auth/[...auth0].js`. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth();
 * ```
 *
 * This will create 4 handlers for the following urls:
 *
 * - `/api/auth/login`: log the user in to your app by redirecting them to your identity provider.
 * - `/api/auth/callback`: The page that your identity provider will redirect the user back to on login.
 * - `/api/auth/logout`: log the user out of your app.
 * - `/api/auth/me`: View the user profile JSON (used by the {@link UseUser} hook)
 *
 * @category Server
 */
export type HandleAuth = (userHandlers?: Handlers) => NextApiHandler;

export type OnError = (req: NextApiRequest, res: NextApiResponse, error: HandlerError) => Promise<void> | void;

/**
 * @ignore
 */
const defaultOnError: OnError = (_req, res, error) => {
  console.error(error);
  res.status(error.status || 500).end();
};

/**
 * @ignore
 */
export default function handlerFactory({
  handleLogin,
  handleLogout,
  handleCallback,
  handleProfile
}: {
  handleLogin: HandleLogin;
  handleLogout: HandleLogout;
  handleCallback: HandleCallback;
  handleProfile: HandleProfile;
}): HandleAuth {
  return ({ onError, ...handlers }: Handlers = {}): NextApiHandler<void> => {
    const customHandlers: ApiHandlers = {
      login: handleLogin,
      logout: handleLogout,
      callback: handleCallback,
      me: (handlers as ApiHandlers).profile || handleProfile,
      ...handlers
    };
    return async (req, res): Promise<void> => {
      let {
        query: { auth0: route }
      } = req;

      route = Array.isArray(route) ? route[0] : /* c8 ignore next */ route;

      try {
        const handler = route && customHandlers[route];
        if (handler) {
          await handler(req, res);
        } else {
          res.status(404).end();
        }
      } catch (error) {
        await (onError || defaultOnError)(req, res, error as HandlerError);
        if (!res.writableEnded) {
          // 200 is the default, so we assume it has not been set in the custom error handler if it equals 200
          res.status(res.statusCode === 200 ? 500 : res.statusCode).end();
        }
      }
    };
  };
}
