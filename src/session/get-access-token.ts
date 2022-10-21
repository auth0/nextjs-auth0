import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import type { errors } from 'openid-client';
import { ClientFactory, IdentityProviderError } from '../auth0-session';
import { AccessTokenError, AccessTokenErrorCode } from '../utils/errors';
import { intersect, match } from '../utils/array';
import { Session, SessionCache, fromTokenSet } from '../session';
import { AuthorizationParameters, NextConfig } from '../config';

export type AfterRefresh = (req: NextApiRequest, res: NextApiResponse, session: Session) => Promise<Session> | Session;

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
 * Get an access token to access an external API.
 *
 * @throws {@link AccessTokenError}
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
    let session = await sessionCache.get(req, res);
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

    if (accessTokenRequest && accessTokenRequest.scopes) {
      const persistedScopes = session.accessTokenScope;
      if (!persistedScopes || persistedScopes.length === 0) {
        throw new AccessTokenError(
          AccessTokenErrorCode.INSUFFICIENT_SCOPE,
          'An access token with the requested scopes could not be provided. The user will need to sign in again.'
        );
      }

      const matchingScopes = intersect(accessTokenRequest.scopes, persistedScopes.split(' '));
      if (!match(accessTokenRequest.scopes, [...matchingScopes])) {
        throw new AccessTokenError(
          AccessTokenErrorCode.INSUFFICIENT_SCOPE,
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
        AccessTokenErrorCode.EXPIRED_ACCESS_TOKEN,
        'The access token expired and a refresh token is not available. The user will need to sign in again.'
      );
    }

    if (accessTokenRequest?.refresh && !session.refreshToken) {
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
      (session.refreshToken && accessTokenRequest && accessTokenRequest.refresh)
    ) {
      const client = await getClient();
      let tokenSet;
      try {
        tokenSet = await client.refresh(session.refreshToken, {
          exchangeBody: accessTokenRequest?.authorizationParams
        });
      } catch (e) {
        throw new AccessTokenError(
          AccessTokenErrorCode.FAILED_REFRESH_GRANT,
          'The request to refresh the access token failed.',
          new IdentityProviderError(e as errors.OPError)
        );
      }

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

      await sessionCache.set(req, res, session);

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
