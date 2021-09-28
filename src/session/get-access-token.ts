import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { ClientFactory } from '../auth0-session';
import { AccessTokenError } from '../utils/errors';
import { intersect, match } from '../utils/array';
import { Session, SessionCache, fromTokenSet } from '../session';
import { NextConfig } from '../config';

export type AfterRefresh = (req: NextApiRequest, res: NextApiResponse, session: Session) => Promise<Session> | Session;

/**
 * Custom options to get an Access Token.
 *
 * @category Server
 */
export interface AccessTokenRequest {
  /**
   * A list of desired scopes for your Access Token.
   */
  scopes?: string[];

  /**
   * If set to `true`, a new Access Token will be requested with the Refresh Token grant, regardless of whether
   * the Access Token has expired or not.
   */
  refresh?: boolean;

  /**
   * When the Access Token Request refreshes the tokens using the Refresh Grant the Session is updated with new tokens.
   * Use this to modify the session after it is refreshed.
   * Usually used to keep updates in sync with the {@Link AfterCallback} hook.
   * See also the {@Link AfterRefetch} hook
   *
   * ### Modify the session after refresh
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
}

/**
 * Response from requesting an Access Token.
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
 * Get an Access Token to access an external API.
 *
 * @category Server
 */
export type GetAccessToken = (
  req: IncomingMessage | NextApiRequest,
  res: ServerResponse | NextApiResponse,
  accessTokenRequest?: AccessTokenRequest
) => Promise<GetAccessTokenResult>;

/**
 * @ignore
 */
export default function accessTokenFactory(
  config: NextConfig,
  getClient: ClientFactory,
  sessionCache: SessionCache
): GetAccessToken {
  return async (req, res, accessTokenRequest): Promise<GetAccessTokenResult> => {
    let session = sessionCache.get(req, res);
    if (!session) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid session.');
    }

    if (!session.accessToken && !session.refreshToken) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid access token.');
    }

    if (!session.accessTokenExpiresAt) {
      throw new AccessTokenError(
        'access_token_expired',
        'Expiration information for the access token is not available. The user will need to sign in again.'
      );
    }

    if (accessTokenRequest && accessTokenRequest.scopes) {
      const persistedScopes = session.accessTokenScope;
      if (!persistedScopes || persistedScopes.length === 0) {
        throw new AccessTokenError(
          'insufficient_scope',
          'An access token with the requested scopes could not be provided. The user will need to sign in again.'
        );
      }

      const matchingScopes = intersect(accessTokenRequest.scopes, persistedScopes.split(' '));
      if (!match(accessTokenRequest.scopes, [...matchingScopes])) {
        throw new AccessTokenError(
          'insufficient_scope',
          `Could not retrieve an access token with scopes "${accessTokenRequest.scopes.join(
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
        'access_token_expired',
        'The access token expired and a refresh token is not available. The user will need to sign in again.'
      );
    }

    // Check if the token has expired.
    // There is an edge case where we might have some clock skew where our code assumes the token is still valid.
    // Adding a skew of 1 minute to compensate.
    if (
      (session.refreshToken && session.accessTokenExpiresAt * 1000 - 60000 < Date.now()) ||
      (session.refreshToken && accessTokenRequest && accessTokenRequest.refresh)
    ) {
      const client = await getClient();
      const tokenSet = await client.refresh(session.refreshToken);

      // Update the session.
      const newSession = fromTokenSet(tokenSet, config);
      Object.assign(session, {
        ...newSession,
        refreshToken: newSession.refreshToken || session.refreshToken,
        user: { ...session.user, ...newSession.user }
      });

      if (accessTokenRequest?.afterRefresh) {
        session = await accessTokenRequest.afterRefresh(req as NextApiRequest, res as NextApiResponse, session);
      }

      sessionCache.set(req, res, session as Session);

      // Return the new access token.
      return {
        accessToken: tokenSet.access_token
      };
    }

    // We don't have an access token.
    if (!session.accessToken) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid access token.');
    }

    // The access token is not expired and has sufficient scopes;
    return {
      accessToken: session.accessToken
    };
  };
}
