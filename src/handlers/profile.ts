import { NextApiResponse, NextApiRequest } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionCache, Session, fromJson, GetAccessToken } from '../session';
import { assertReqRes } from '../utils/assert';
import { ProfileHandlerError, HandlerErrorCause } from '../utils/errors';
import { AppRouteHandlerFnContext, AuthHandler, getHandler, Handler, OptionsProvider } from './router-helpers';
import { GetClient } from '../auth0-session/client/abstract-client';
import { GetConfig } from '../config';
import { Auth0NextApiRequest, Auth0NextRequest } from '../http';

/**
 * After refetch handler for page router {@link AfterRefetchPageRoute} and app router {@link AfterRefetchAppRoute}.
 *
 * @category Server
 */
export type AfterRefetch = AfterRefetchPageRoute | AfterRefetchAppRoute;

/**
 * After refetch handler for page router.
 *
 * @category Server
 */
export type AfterRefetchPageRoute = (
  req: NextApiRequest,
  res: NextApiResponse,
  session: Session
) => Promise<Session> | Session;

/**
 * After refetch handler for app router.
 *
 * @category Server
 */
export type AfterRefetchAppRoute = (req: NextRequest, session: Session) => Promise<Session> | Session;

/**
 * Options to customize the profile handler.
 *
 * @see {@link HandleProfile}
 *
 * @category Server
 */
export type ProfileOptions = {
  /**
   * If set to `true` this will refetch the user profile information from `/userinfo` and save it
   * to the session.
   */
  refetch?: boolean;

  /**
   * Like {@link AfterCallback}  and {@link AfterRefresh} when a session is created, you can use
   * this function to validate or add/remove claims after the session is updated. Will only run if
   * {@link ProfileOptions.refetch} is `true`.
   */
  afterRefetch?: AfterRefetch;
};

/**
 * Options provider for the default profile handler.
 * Use this to generate options that depend on values from the request.
 *
 * @category Server
 */
export type ProfileOptionsProvider = OptionsProvider<ProfileOptions>;

/**
 * Use this to customize the default profile handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleProfile } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   profile: handleProfile({ refetch: true })
 * });
 * ```
 *
 * @example Pass a function that receives the request and returns an options object
 *
 * ```js
 * // pages/api/auth/[auth0].js
 * import { handleAuth, handleProfile } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   profile: handleProfile((req) => {
 *     return { refetch: true };
 *   })
 * });
 * ```
 *
 * This is useful for generating options that depend on values from the request.
 *
 * @example Override the profile handler
 *
 * ```js
 * import { handleAuth, handleProfile } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   profile: async (req, res) => {
 *     try {
 *       await handleProfile(req, res, { refetch: true });
 *     } catch (error) {
 *       console.error(error);
 *     }
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type HandleProfile = AuthHandler<ProfileOptions>;

/**
 * The handler for the `/api/auth/me` API route.
 *
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type ProfileHandler = Handler<ProfileOptions>;

/**
 * @ignore
 */
export default function profileHandler(
  getConfig: GetConfig,
  getClient: GetClient,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
): HandleProfile {
  const appRouteHandler = appRouteHandlerFactory(getConfig, getClient, getAccessToken, sessionCache);
  const pageRouteHandler = pageRouteHandlerFactory(getConfig, getClient, getAccessToken, sessionCache);

  return getHandler<ProfileOptions>(appRouteHandler, pageRouteHandler) as HandleProfile;
}

/**
 * @ignore
 */
const appRouteHandlerFactory: (
  getConfig: GetConfig,
  getClient: GetClient,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
) => (req: NextRequest, ctx: AppRouteHandlerFnContext, options?: ProfileOptions) => Promise<Response> | Response =
  (getConfig, getClient, getAccessToken, sessionCache) =>
  async (req, _ctx, options = {}) => {
    try {
      const config = await getConfig(new Auth0NextRequest(req));
      const client = await getClient(config);
      const res = new NextResponse();

      if (!(await sessionCache.isAuthenticated(req, res))) {
        const emptyRes = new NextResponse(null, { status: 204 });
        res.headers.forEach((val, key) => emptyRes.headers.set(key, val));
        return emptyRes;
      }

      const session = (await sessionCache.get(req, res)) as Session;
      res.headers.set('Cache-Control', 'no-store');

      if (options.refetch) {
        const { accessToken } = await getAccessToken(req, res);
        if (!accessToken) {
          throw new Error('No access token available to refetch the profile');
        }

        const userInfo = await client.userinfo(accessToken);

        let newSession = fromJson({
          ...session,
          user: {
            ...session.user,
            ...userInfo
          }
        }) as Session;

        if (options.afterRefetch) {
          newSession = await (options.afterRefetch as AfterRefetchAppRoute)(req, newSession);
        }

        await sessionCache.set(req, res, newSession);

        return NextResponse.json(newSession.user, res);
      }

      return NextResponse.json(session.user, res);
    } catch (e) {
      throw new ProfileHandlerError(e as HandlerErrorCause);
    }
  };

/**
 * @ignore
 */
const pageRouteHandlerFactory: (
  getConfig: GetConfig,
  getClient: GetClient,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
) => (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void> =
  (getConfig, getClient, getAccessToken, sessionCache) =>
  async (req: NextApiRequest, res: NextApiResponse, options = {}): Promise<void> => {
    try {
      assertReqRes(req, res);
      const config = await getConfig(new Auth0NextApiRequest(req));
      const client = await getClient(config);

      if (!(await sessionCache.isAuthenticated(req, res))) {
        res.status(204).end();
        return;
      }

      const session = (await sessionCache.get(req, res)) as Session;
      res.setHeader('Cache-Control', 'no-store');

      if (options.refetch) {
        const { accessToken } = await getAccessToken(req, res);
        if (!accessToken) {
          throw new Error('No access token available to refetch the profile');
        }

        const userInfo = await client.userinfo(accessToken);

        let newSession = fromJson({
          ...session,
          user: {
            ...session.user,
            ...userInfo
          }
        }) as Session;

        if (options.afterRefetch) {
          newSession = await (options.afterRefetch as AfterRefetchPageRoute)(req, res, newSession);
        }

        await sessionCache.set(req, res, newSession);

        res.json(newSession.user);
        return;
      }

      res.json(session.user);
    } catch (e) {
      throw new ProfileHandlerError(e as HandlerErrorCause);
    }
  };
