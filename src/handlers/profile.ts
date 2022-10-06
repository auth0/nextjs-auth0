import { IncomingMessage } from 'http';
import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory } from '../auth0-session';
import { SessionCache, Session, fromJson, GetAccessToken } from '../session';
import { assertReqRes } from '../utils/assert';
import { ProfileHandlerError, HandlerErrorCause } from '../utils/errors';

export type AfterRefetch = (req: NextApiRequest, res: NextApiResponse, session: Session) => Promise<Session> | Session;

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
 * TODO: Complete
 */
export type ProfileOptionsProvider = (req: NextApiRequest) => ProfileOptions;

/**
 * TODO: Complete
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
  const profile: ProfileHandler = async (req: NextApiRequest, res: NextApiResponse, options = {}): Promise<void> => {
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
          newSession = await options.afterRefetch(req, res, newSession);
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
  return (
    reqOrOptions: NextApiRequest | ProfileOptionsProvider | ProfileOptions,
    res?: NextApiResponse,
    options?: ProfileOptions
  ): any => {
    if (reqOrOptions instanceof IncomingMessage && res) {
      return profile(reqOrOptions, res, options);
    }
    if (typeof reqOrOptions === 'function') {
      return (req: NextApiRequest, res: NextApiResponse) => profile(req, res, reqOrOptions(req));
    }
    return (req: NextApiRequest, res: NextApiResponse) => profile(req, res, reqOrOptions as ProfileOptions);
  };
}
