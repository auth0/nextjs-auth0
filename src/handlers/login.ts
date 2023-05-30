import { NextApiResponse, NextApiRequest } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import {
  AuthorizationParameters,
  HandleLogin as BaseHandleLogin,
  LoginOptions as BaseLoginOptions
} from '../auth0-session';
import toSafeRedirect from '../utils/url-helpers';
import { assertReqRes } from '../utils/assert';
import { BaseConfig, NextConfig } from '../config';
import { HandlerErrorCause, LoginHandlerError } from '../utils/errors';
import { Auth0NextApiRequest, Auth0NextApiResponse, Auth0NextRequest, Auth0NextResponse } from '../http';
import { AppRouteHandlerFnContext, getHandler, OptionsProvider, Handler, AuthHandler } from './router-helpers';

/**
 * Use this to store additional state for the user before they visit the identity provider to log in.
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * const getLoginState = (req, loginOptions) => {
 *   return { basket_id: getBasketId(req) };
 * };
 *
 * export default handleAuth({
 *   async login(req, res) {
 *     try {
 *       await handleLogin(req, res, { getLoginState });
 *     } catch (error) {
 *       res.status(error.status || 500).end();
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type GetLoginState = GetLoginStatePageRoute | GetLoginStateAppRoute;

export type GetLoginStatePageRoute = (req: NextApiRequest, options: LoginOptions) => { [key: string]: any };
export type GetLoginStateAppRoute = (req: NextApiRequest, options: LoginOptions) => { [key: string]: any };

/**
 * Authorization params to pass to the login handler.
 *
 * @category Server
 */
export interface AuthorizationParams extends Partial<AuthorizationParameters> {
  /**
   * The name of an OAuth2/social connection. Use it to directly show that
   * identity provider's login page, skipping the Universal Login page itself.
   * By default no connection is specified, so the Universal Login page will be displayed.
   *
   * ```js
   * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
   *
   * export default handleAuth({
   *   login: async (req, res) => {
   *     try {
   *       await handleLogin(req, res, {
   *         // Get the connection name from the Auth0 Dashboard
   *         authorizationParams: { connection: 'github' }
   *       });
   *     } catch (error) {
   *       console.error(error);
   *     }
   *   }
   * });
   * ```
   */
  connection?: string;

  /**
   * Provider scopes for OAuth2/social connections, such as GitHub or Google.
   *
   * ```js
   * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
   *
   * export default handleAuth({
   *   login: async (req, res) => {
   *     try {
   *       await handleLogin(req, res, {
   *         authorizationParams: {
   *           connection: 'github',
   *           connection_scope: 'public_repo read:user'
   *         }
   *       });
   *     } catch (error) {
   *       console.error(error);
   *     }
   *   }
   * });
   * ```
   */
  connection_scope?: string;

  /**
   * The invitation id to join an organization.
   *
   * To create a link for your user's to accept an organization invite, read the `invitation` and `organization`
   * query params and pass them to the authorization server to log the user in:
   *
   * ```js
   * // pages/api/invite.js
   * import { handleLogin } from '@auth0/nextjs-auth0';
   *
   * export default async function invite(req, res) {
   *   try {
   *     const { invitation, organization } = req.query;
   *     if (!invitation) {
   *       res.status(400).end('Missing "invitation" parameter');
   *     }
   *     await handleLogin(req, res, {
   *       authorizationParams: {
   *         invitation,
   *         organization
   *       }
   *     });
   *   } catch (error) {
   *     res.status(error.status || 500).end();
   *   }
   * } ;
   * ```
   *
   * Your invite url can then take the format:
   * `https://example.com/api/invite?invitation=invitation_id&organization=org_id`.
   */
  invitation?: string;

  /**
   * This is useful to specify instead of {@link NextConfig.organization} when your app has multiple
   * organizations. It should match {@link CallbackOptions.organization}.
   */
  organization?: string;

  /**
   * Provides a hint to Auth0 as to what flow should be displayed. The default behavior is to show a
   * login page but you can override this by passing 'signup' to show the signup page instead.
   *
   * This only affects the New Universal Login Experience.
   */
  screen_hint?: string;
}

/**
 * Options to customize the login handler.
 *
 * @see {@link HandleLogin}
 *
 * @category Server
 */
export interface LoginOptions {
  /**
   * Override the default {@link BaseConfig.authorizationParams authorizationParams}.
   */
  authorizationParams?: AuthorizationParams;

  /**
   *  URL to return to after login. Overrides the default in {@link BaseConfig.baseURL}.
   */
  returnTo?: string;

  /**
   *  Generate a unique state value for use during login transactions.
   */
  getLoginState?: GetLoginState;
}

/**
 * Options provider for the default login handler.
 * Use this to generate options that depend on values from the request.
 *
 * @category Server
 */
export type LoginOptionsProvider = OptionsProvider<LoginOptions>;

/**
 * Use this to customize the default login handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   login: handleLogin({
 *     authorizationParams: { connection: 'github' }
 *   })
 * });
 * ```
 *
 * @example Pass a function that receives the request and returns an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   login: handleLogin((req) => {
 *     return {
 *       authorizationParams: { connection: 'github' }
 *     };
 *   })
 * });
 * ```
 *
 * This is useful for generating options that depend on values from the request.
 *
 * @example Override the login handler
 *
 * ```js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   login: async (req, res) => {
 *     try {
 *       await handleLogin(req, res, {
 *         authorizationParams: { connection: 'github' }
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
export type HandleLogin = AuthHandler<LoginOptions>;

/**
 * The handler for the `/api/auth/login` API route.
 *
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type LoginHandler = Handler<LoginOptions>;

/**
 * @ignore
 */
export default function handleLoginFactory(
  handler: BaseHandleLogin,
  nextConfig: NextConfig,
  baseConfig: BaseConfig
): HandleLogin {
  const appRouteHandler = appRouteHandlerFactory(handler, nextConfig, baseConfig);
  const pageRouteHandler = pageRouteHandlerFactory(handler, nextConfig, baseConfig);

  return getHandler<LoginOptions>(appRouteHandler, pageRouteHandler) as HandleLogin;
}

const applyOptions = (
  req: NextApiRequest | NextRequest,
  options: LoginOptions,
  dangerousReturnTo: string | undefined | null,
  nextConfig: NextConfig,
  baseConfig: BaseConfig
): BaseLoginOptions => {
  let opts: BaseLoginOptions;
  let getLoginState: GetLoginState | undefined;
  ({ getLoginState, ...opts } = options);
  if (dangerousReturnTo) {
    const safeBaseUrl = new URL(options.authorizationParams?.redirect_uri || baseConfig.baseURL);
    const returnTo = toSafeRedirect(dangerousReturnTo, safeBaseUrl);
    opts = { ...opts, returnTo };
  }
  if (nextConfig.organization) {
    opts = {
      ...opts,
      authorizationParams: { organization: nextConfig.organization, ...opts.authorizationParams }
    };
  }
  if (getLoginState) {
    opts.getLoginState = (_opts) => (getLoginState as GetLoginState)(req as any, _opts as any);
  }
  return opts;
};

const appRouteHandlerFactory: (
  handler: BaseHandleLogin,
  nextConfig: NextConfig,
  baseConfig: BaseConfig
) => (req: NextRequest, ctx: AppRouteHandlerFnContext, options?: LoginOptions) => Promise<Response> | Response =
  (handler, nextConfig, baseConfig) =>
  async (req, _ctx, options = {}) => {
    try {
      const url = new URL(req.url);
      const dangerousReturnTo = url.searchParams.get('returnTo');

      const auth0Res = new Auth0NextResponse(new NextResponse());
      await handler(
        new Auth0NextRequest(req),
        auth0Res,
        applyOptions(req, options, dangerousReturnTo, nextConfig, baseConfig) as BaseLoginOptions
      );
      return auth0Res.res;
    } catch (e) {
      throw new LoginHandlerError(e as HandlerErrorCause);
    }
  };

const pageRouteHandlerFactory: (
  handler: BaseHandleLogin,
  nextConfig: NextConfig,
  baseConfig: BaseConfig
) => (req: NextApiRequest, res: NextApiResponse, options?: LoginOptions) => Promise<void> | void =
  (handler, nextConfig, baseConfig) =>
  async (req, res, options = {}) => {
    try {
      assertReqRes(req, res);
      const dangerousReturnTo =
        req.query.returnTo && Array.isArray(req.query.returnTo) ? req.query.returnTo[0] : req.query.returnTo;

      return await handler(
        new Auth0NextApiRequest(req),
        new Auth0NextApiResponse(res),
        applyOptions(req, options, dangerousReturnTo, nextConfig, baseConfig) as BaseLoginOptions
      );
    } catch (e) {
      throw new LoginHandlerError(e as HandlerErrorCause);
    }
  };
