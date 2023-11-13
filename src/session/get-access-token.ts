import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { AuthorizationParameters } from '../auth0-session';
import { AccessTokenError, AccessTokenErrorCode } from '../utils/errors';
import { intersect, match } from '../utils/array';
import { Session, SessionCache, fromTokenEndpointResponse, get, set } from '../session';
import { GetClient } from '../auth0-session/client/abstract-client';
import { GetConfig } from '../config';
import { getAuth0ReqRes } from './cache';
import { Auth0NextRequestCookies } from '../http';

/**
 * After refresh handler for page router {@link AfterRefreshPageRoute} and app router {@link AfterRefreshAppRoute}.
 *
 * @category Server
 */
export type AfterRefresh = AfterRefreshPageRoute | AfterRefreshAppRoute;

/**
 * After refresh handler for page router.
 *
 * @category Server
 */
export type AfterRefreshPageRoute = (
  req: NextApiRequest | IncomingMessage,
  res: NextApiResponse | ServerResponse,
  session: Session
) => Promise<Session> | Session;

/**
 * After refresh handler for app router.
 *
 * @category Server
 */
export type AfterRefreshAppRoute = (session: Session) => Promise<Session> | Session;

/**
 * Custom options to get an access token.
 *
 * @category Server
 */
export interface AccessTokenRequest {
  /**
   * A list of desired scopes for your access token.
   */
  scopes?: string[];

  /**
   * If set to `true`, a new access token will be requested with the refresh token grant, regardless of whether
   * the access token has expired or not.
   *
   * **IMPORTANT** You need to request the `offline_access` scope on login to get a refresh token
   * from Auth0.
   */
  refresh?: boolean;

  /**
   * When the access token request refreshes the tokens using the refresh grant the session is updated with new tokens.
   * Use this to modify the session after it is refreshed.
   * Usually used to keep updates in sync with the {@link AfterCallback} hook.
   *
   * @see also the {@link AfterRefetch} hook.
   *
   * @example Modify the session after refresh
   *
   * ```js
   * // pages/api/my-handler.js
   * import { getAccessToken } from '@auth0/nextjs-auth0';
   *
   * const afterRefresh = (req, res, session) => {
   *   session.user.customProperty = 'foo';
   *   delete session.idToken;
   *   return session;
   * };
   *
   * export default async function MyHandler(req, res) {
   *   const accessToken = await getAccessToken(req, res, {
   *     refresh: true,
   *     afterRefresh,
   *   });
   * };
   * ```
   */
  afterRefresh?: AfterRefresh;

  /**
   * This is useful for sending custom query parameters in the body of the refresh grant request for use in rules.
   */
  authorizationParams?: Partial<AuthorizationParameters>;
}

/**
 * Response from requesting an access token.
 *
 * @category Server
 */
export interface GetAccessTokenResult {
  /**
   * Access token returned from the token cache.
   */
  accessToken?: string | undefined;
}

/**
 * Get an access token to access an external API from the server.
 *
 * **In the App Router:**
 *
 * In a route handler:
 *
 * ```js
 * // app/my-api/route.js
 * import { NextResponse } from 'next/server';
 * import { getAccessToken } from '@auth0/nextjs-auth0';
 *
 * export async function GET() {
 *   const { accessToken } = await getAccessToken();
 *   return NextResponse.json({ foo: 'bar' });
 * }
 *
 * // Or, it's slightly more efficient to use the `req`, `res` args if you're
 * // using another part of the SDK like `withApiAuthRequired` or `getSession`.
 * import { NextResponse } from 'next/server';
 * import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';
 *
 * const GET = withApiAuthRequired(async function GET(req) {
 *   const res = new NextResponse();
 *   const { accessToken } = await getAccessToken(req, res);
 *   return NextResponse.json({ foo: 'bar' }, res);
 * });
 *
 * export { GET };
 * ```
 *
 * In a page or React Server Component:
 *
 * ```js
 * // app/my-page/page.js
 * import { getAccessToken } from '@auth0/nextjs-auth0';
 *
 * export default async function MyPage({ params, searchParams }) {
 *   const { accessToken } = await getAccessToken();
 *   return <h1>My Page</h1>;
 * }
 * ```
 *
 * **Note:** You can't write to the cookie in a React Server Component, so if
 * the access token is refreshed, it won't be persisted in the session.
 *
 * You can also get the access token in a page or route in the Edge Runtime:
 *
 * ```js
 * // app/my-api/route.js
 * import { NextResponse } from 'next/server';
 * import { getAccessToken } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export async function GET() {
 *   const { accessToken } = await getAccessToken();
 *   return NextResponse.json({ foo: 'bar' });
 * }
 *
 * export const runtime = 'edge';
 * ```
 *
 * **Note:** The Edge runtime features are only supported in the App Router.
 *
 * **In the Page Router:**
 *
 * In an API handler:
 *
 * ```js
 * // pages/api/my-api.js
 * import { getAccessToken } from '@auth0/nextjs-auth0';
 *
 * export default async function MyApi(req, res) {
 *   const { accessToken } = await getAccessToken(req, res);
 *   res.status(200).json({ name: 'John Doe' });
 * }
 * ```
 *
 * In a page:
 *
 * ```js
 * // pages/my-page.js
 * import { getAccessToken } from '@auth0/nextjs-auth0';
 *
 * export default function About() {
 *   return <div>About</div>;
 * }
 *
 * export async function getServerSideProps(ctx) {
 *   const { accessToken } = await getAccessToken(ctx.req, ctx.res);
 *   return { props: { foo: 'bar' } };
 * }
 * ```
 *
 * **In middleware:**
 *
 * ```js
 * import { NextResponse } from 'next/server';
 * import { getAccessToken } from '@auth0/nextjs-auth0/edge'; // Note the /edge import

 *
 * export async function middleware(req) {
 *   const res = new NextResponse();
 *   const { accessToken } = await getAccessToken(req, res);
 *   return NextResponse.redirect(new URL('/bar', request.url), res);
 * }
 *
 * export const config = {
 *   matcher: '/foo',
 * };
 * ```
 *
 * @throws {@link AccessTokenError}
 *
 * @category Server
 */
export type GetAccessToken = (
  ...args:
    | [IncomingMessage, ServerResponse, AccessTokenRequest?]
    | [NextApiRequest, NextApiResponse, AccessTokenRequest?]
    | [NextRequest, NextResponse, AccessTokenRequest?]
    | [AccessTokenRequest?]
) => Promise<GetAccessTokenResult>;

/**
 * @ignore
 */
export default function accessTokenFactory(
  getConfig: GetConfig,
  getClient: GetClient,
  sessionCache: SessionCache
): GetAccessToken {
  return async (reqOrOpts?, res?, accessTokenRequest?): Promise<GetAccessTokenResult> => {
    const options = (res ? accessTokenRequest : reqOrOpts) as AccessTokenRequest | undefined;
    const req = (res ? reqOrOpts : undefined) as IncomingMessage | NextApiRequest | undefined;
    const config = await getConfig(req ? getAuth0ReqRes(req, res as any)[0] : new Auth0NextRequestCookies());
    const client = await getClient(config);

    const parts = await get({ sessionCache, req, res });
    let [session] = parts;
    const [, iat] = parts;
    if (!session) {
      throw new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, 'The user does not have a valid session.');
    }

    if (!session.accessToken && !session.refreshToken) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_ACCESS_TOKEN,
        'The user does not have a valid access token.'
      );
    }

    if (!session.accessTokenExpiresAt) {
      throw new AccessTokenError(
        AccessTokenErrorCode.EXPIRED_ACCESS_TOKEN,
        'Expiration information for the access token is not available. The user will need to sign in again.'
      );
    }

    if (options && options.scopes) {
      const persistedScopes = session.accessTokenScope;
      if (!persistedScopes || persistedScopes.length === 0) {
        throw new AccessTokenError(
          AccessTokenErrorCode.INSUFFICIENT_SCOPE,
          'An access token with the requested scopes could not be provided. The user will need to sign in again.'
        );
      }

      const matchingScopes = intersect(options.scopes, persistedScopes.split(' '));
      if (!match(options.scopes, [...matchingScopes])) {
        throw new AccessTokenError(
          AccessTokenErrorCode.INSUFFICIENT_SCOPE,
          `Could not retrieve an access token with scopes "${options.scopes.join(
            ' '
          )}". The user will need to sign in again.`
        );
      }
    }

    // Check if the token has expired.
    // There is an edge case where we might have some clock skew where our code assumes the token is still valid.
    // Adding a skew of 1 minute to compensate.
    if (!session.refreshToken && session.accessTokenExpiresAt * 1000 - 60000 < Date.now()) {
      throw new AccessTokenError(
        AccessTokenErrorCode.EXPIRED_ACCESS_TOKEN,
        'The access token expired and a refresh token is not available. The user will need to sign in again.'
      );
    }

    if (options?.refresh && !session.refreshToken) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
        'A refresh token is required to refresh the access token, but none is present.'
      );
    }

    // Check if the token has expired.
    // There is an edge case where we might have some clock skew where our code assumes the token is still valid.
    // Adding a skew of 1 minute to compensate.
    if (
      (session.refreshToken && session.accessTokenExpiresAt * 1000 - 60000 < Date.now()) ||
      (session.refreshToken && options && options.refresh)
    ) {
      const tokenSet = await client.refresh(session.refreshToken, {
        exchangeBody: options?.authorizationParams
      });

      // Update the session.
      const newSession = fromTokenEndpointResponse(tokenSet, config);
      Object.assign(session, {
        ...newSession,
        refreshToken: newSession.refreshToken || session.refreshToken,
        user: { ...session.user, ...newSession.user }
      });

      if (options?.afterRefresh) {
        if (req) {
          session = await (options.afterRefresh as AfterRefreshPageRoute)(
            req,
            res as NextApiResponse | ServerResponse,
            session
          );
        } else {
          session = await (options.afterRefresh as AfterRefreshAppRoute)(session);
        }
      }

      await set({ sessionCache, req, res, session, iat });

      // Return the new access token.
      return {
        accessToken: tokenSet.access_token
      };
    }

    // We don't have an access token.
    if (!session.accessToken) {
      throw new AccessTokenError(
        AccessTokenErrorCode.MISSING_ACCESS_TOKEN,
        'The user does not have a valid access token.'
      );
    }

    // The access token is not expired and has sufficient scopes.
    return {
      accessToken: session.accessToken
    };
  };
}
