import { NextApiResponse, NextApiRequest } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { ClientFactory } from '../auth0-session';
import { SessionCache, Session, fromJson, GetAccessToken } from '../session';
import { assertReqRes } from '../utils/assert';
import { ProfileHandlerError, HandlerErrorCause } from '../utils/errors';
import { IncomingMessage, ServerResponse } from 'http';

export type AfterRefetch = AfterRefetchPageRoute | AfterRefetchAppRoute;

export type AfterRefetchPageRoute = (
  req: NextApiRequest | IncomingMessage,
  res: NextApiRequest | ServerResponse,
  session: Session
) => Promise<Session> | Session;

export type AfterRefetchAppRoute = (session: Session) => Promise<Session> | Session;

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
export type ProfileOptionsProvider = (req: NextApiRequest | NextRequest) => ProfileOptions;

/**
 * Use this to customize the default profile handler without overriding it.
 * You can still override the handler if needed.
 *
 * @example Pass an options object
 *
 * ```js
 * // pages/api/auth/[...auth0].js
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
 * // pages/api/auth/[...auth0].js
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
export type HandleProfile = {
  (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions): Promise<void>;
  (provider: ProfileOptionsProvider): ProfileHandler;
  (options: ProfileOptions): ProfileHandler;
};

/**
 * The handler for the `/api/auth/me` API route.
 *
 * @throws {@link HandlerError}
 *
 * @category Server
 */
export type ProfileHandler = (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void>;

/**
 * @ignore
 */
export default function profileHandler(
  getClient: ClientFactory,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
): HandleProfile {
  const appRouteHandler = appRouteHandlerFactory(getClient, getAccessToken, sessionCache);
  const pageRouteHandler = pageRouteHandlerFactory(getClient, getAccessToken, sessionCache);

  return (
    reqOrOptions: NextApiRequest | ProfileOptionsProvider | ProfileOptions,
    res?: NextApiResponse,
    options?: ProfileOptions
  ): any => {
    if (typeof Request !== undefined && reqOrOptions instanceof Request) {
      return appRouteHandler(reqOrOptions as NextRequest, options);
    }
    if ('socket' in reqOrOptions && res) {
      return pageRouteHandler(reqOrOptions as NextApiRequest, res as NextApiResponse, options);
    }
    return (req: NextApiRequest | NextRequest, res: NextApiResponse) => {
      const opts = (typeof reqOrOptions === 'function' ? reqOrOptions(req) : reqOrOptions) as ProfileOptions;

      if (typeof Request !== undefined && req instanceof Request) {
        return appRouteHandler(req as NextRequest, opts);
      }
      return pageRouteHandler(req as NextApiRequest, res as NextApiResponse, opts);
    };
  };
}

const appRouteHandlerFactory: (
  getClient: ClientFactory,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
) => (req: NextRequest, options?: ProfileOptions) => Promise<Response> | Response =
  (getClient, getAccessToken, sessionCache) =>
  async (req, options = {}) => {
    try {
      const res = new NextResponse();

      if (!(await sessionCache.isAuthenticated(req, res))) {
        return new Response(null, { status: 204 });
      }

      const session = (await sessionCache.get(req, res)) as Session;
      res.headers.set('Cache-Control', 'no-store');

      if (options.refetch) {
        const { accessToken } = await getAccessToken();
        if (!accessToken) {
          throw new Error('No access token available to refetch the profile');
        }

        const client = await getClient();
        const userInfo = await client.userinfo(accessToken);

        let newSession = fromJson({
          ...session,
          user: {
            ...session.user,
            ...userInfo
          }
        }) as Session;

        if (options.afterRefetch) {
          newSession = await (options.afterRefetch as AfterRefetchAppRoute)(newSession);
        }

        await sessionCache.set(req, res, newSession);

        return NextResponse.json(session.user, res);
      }

      return NextResponse.json(session.user, res);
    } catch (e) {
      throw new ProfileHandlerError(e as HandlerErrorCause);
    }
  };

const pageRouteHandlerFactory: (
  getClient: ClientFactory,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
) => (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void> =
  (getClient, getAccessToken, sessionCache) =>
  async (req: NextApiRequest, res: NextApiResponse, options = {}): Promise<void> => {
    try {
      assertReqRes(req, res);

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

        const client = await getClient();
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
