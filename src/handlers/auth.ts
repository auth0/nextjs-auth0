import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import { NextRequest } from 'next/server';
import { HandleLogin } from './login';
import { HandleLogout } from './logout';
import { HandleCallback } from './callback';
import { HandleBackchannelLogout } from './backchannel-logout';
import { HandleProfile } from './profile';
import { HandlerError } from '../utils/errors';
import {
  AppRouteHandlerFn,
  AppRouteHandlerFnContext,
  NextAppRouterHandler,
  NextPageRouterHandler
} from './router-helpers';
import { isRequest } from '../utils/req-helpers';

/**
 * If you want to add some custom behavior to the default auth handlers, you can pass in custom handlers for
 * `login`, `logout`, `callback`, and `profile`. For example:
 *
 * ```js
 * // pages/api/auth/[auth0].js
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
 * // pages/api/auth/[auth0].js
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
 * // pages/api/auth/[auth0].js
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

/**
 * @ignore
 */
type ApiHandlers = { [key: string]: NextPageRouterHandler | NextAppRouterHandler };

/**
 * @ignore
 */
type ErrorHandlers = {
  onError?: PageRouterOnError | AppRouterOnError;
};

/**
 * The main way to use the server SDK.
 *
 * *Page Router*
 *
 * Simply set the environment variables per {@link ConfigParameters} then create the file
 * `pages/api/auth/[auth0].js`. For example:
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth();
 * ```

 * *App Router*
 *
 * Simply set the environment variables per {@link ConfigParameters} then create the file
 * `app/api/auth/[auth0]/route.js`. For example:
 *
 * ```js
 * // app/api/auth/[auth0]/route.js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * export const GET = handleAuth();
 * ```
 *
 * This will create 4 handlers for the following urls:
 *
 * - `/api/auth/login`: log the user in to your app by redirecting them to your identity provider.
 * - `/api/auth/callback`: The page that your identity provider will redirect the user back to on login.
 * - `/api/auth/logout`: log the user out of your app.
 * - `/api/auth/me`: View the user profile JSON (used by the {@link UseUser} hook).
 *
 * @category Server
 */
// any is required for app router ts check
export type HandleAuth = (userHandlers?: Handlers) => NextApiHandler | AppRouteHandlerFn | any;

/**
 * Error handler for the default auth routes.
 *
 * Use this to define an error handler for all the default routes in a single place. For example:
 *
 * ```js
 * export default handleAuth({
 *   onError(req, res, error) {
 *     errorLogger(error);
 *     // You can finish the response yourself if you want to customize
 *     // the status code or redirect the user
 *     // res.writeHead(302, {
 *     //     Location: '/custom-error-page'
 *     // });
 *     // res.end();
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type PageRouterOnError = (
  req: NextApiRequest,
  res: NextApiResponse,
  error: HandlerError
) => Promise<void> | void;
export type AppRouterOnError = (req: NextRequest, error: HandlerError) => Promise<Response | void> | Response | void;

/**
 * @ignore
 */
const defaultPageRouterOnError: PageRouterOnError = (_req, res, error) => {
  console.error(error);
  res.status(error.status || 500).end();
};

/**
 * @ignore
 */
const defaultAppRouterOnError: AppRouterOnError = (_req, error) => {
  console.error(error);
};

/**
 * @ignore
 */
export default function handlerFactory({
  handleLogin,
  handleLogout,
  handleCallback,
  handleProfile,
  handleBackchannelLogout
}: {
  handleLogin: HandleLogin;
  handleLogout: HandleLogout;
  handleCallback: HandleCallback;
  handleProfile: HandleProfile;
  handleBackchannelLogout: HandleBackchannelLogout;
}): HandleAuth {
  return ({ onError, ...handlers }: Handlers = {}): NextApiHandler<void> | AppRouteHandlerFn => {
    const customHandlers: ApiHandlers = {
      login: handleLogin,
      logout: handleLogout,
      callback: handleCallback,
      'backchannel-logout': handleBackchannelLogout,
      me: (handlers as ApiHandlers).profile || handleProfile,
      ...handlers
    };

    const appRouteHandler = appRouteHandlerFactory(customHandlers, onError as AppRouterOnError);
    const pageRouteHandler = pageRouteHandlerFactory(customHandlers, onError as PageRouterOnError);

    return (req: NextRequest | NextApiRequest, resOrCtx: NextApiResponse | AppRouteHandlerFnContext) => {
      if (isRequest(req)) {
        return appRouteHandler(req as NextRequest, resOrCtx as AppRouteHandlerFnContext);
      }
      return pageRouteHandler(req as NextApiRequest, resOrCtx as NextApiResponse);
    };
  };
}

/**
 * @ignore
 */
const appRouteHandlerFactory: (customHandlers: ApiHandlers, onError?: AppRouterOnError) => AppRouteHandlerFn =
  (customHandlers, onError) => async (req: NextRequest, ctx) => {
    const { params } = ctx;
    let route = (await params).auth0;

    if (Array.isArray(route)) {
      let otherRoutes;
      [route, ...otherRoutes] = route;
      if (otherRoutes.length) {
        return new Response(null, { status: 404 });
      }
    }

    const handler = route && customHandlers.hasOwnProperty(route) && customHandlers[route];
    try {
      if (handler) {
        return await (handler as AppRouteHandlerFn)(req, ctx);
      } else {
        return new Response(null, { status: 404 });
      }
    } catch (error) {
      const res = await (onError || defaultAppRouterOnError)(req, error as HandlerError);
      return res || new Response(null, { status: error.status || 500 });
    }
  };

/**
 * @ignore
 */
const pageRouteHandlerFactory: (customHandlers: ApiHandlers, onError?: PageRouterOnError) => NextApiHandler =
  (customHandlers, onError) =>
  async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    let {
      query: { auth0: route }
    } = req;

    if (Array.isArray(route)) {
      let otherRoutes;
      [route, ...otherRoutes] = route;
      if (otherRoutes.length) {
        res.status(404).end();
        return;
      }
    }

    try {
      const handler = route && customHandlers.hasOwnProperty(route) && customHandlers[route];
      if (handler) {
        await (handler as NextApiHandler)(req, res);
      } else {
        res.status(404).end();
      }
    } catch (error) {
      await (onError || defaultPageRouterOnError)(req, res, error as HandlerError);
      if (!res.writableEnded) {
        // 200 is the default, so we assume it has not been set in the custom error handler if it equals 200
        res.status(res.statusCode === 200 ? 500 : res.statusCode).end();
      }
    }
  };
