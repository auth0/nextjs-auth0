import { NextApiRequest, NextApiResponse } from 'next';
import AccessTokenError from './access-token-error';
import { intersect, match } from '../utils/array';
import { ITokenCache, AccessTokenRequest, AccessTokenResponse } from './token-cache';
import { CookieStore, Config } from '../auth0-session';

export default class SessionTokenCache implements ITokenCache {
  constructor(
    private config: Config,
    private store: CookieStore,
    private req: NextApiRequest,
    private res: NextApiResponse
  ) {}

  async getAccessToken(accessTokenRequest: AccessTokenRequest = {}): Promise<AccessTokenResponse> {
    const session = await this.store.get(this.req, this.res);
    if (!session) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid session.');
    }

    if (!session.accessToken && !session.refreshToken) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid access token.');
    }

    const { access_token: accessToken, isExpired, refresh } = session.accessToken;

    if (accessTokenRequest && accessTokenRequest.scopes) {
      const persistedScopes = this.config.authorizationParams.scope;
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
    if (!session.refreshToken && isExpired()) {
      throw new AccessTokenError(
        'access_token_expired',
        'The access token expired and a refresh token is not available. The user will need to sign in again.'
      );
    }

    // Check if the token has expired.
    if (session.refreshToken && (isExpired() || accessTokenRequest.refresh)) {
      const newAccessToken = await refresh();

      // Return the new access token.
      return {
        accessToken: newAccessToken.access_token
      };
    }

    // We don't have an access token.
    if (!accessToken) {
      throw new AccessTokenError('invalid_session', 'The user does not have a valid access token.');
    }

    // The access token is not expired and has sufficient scopes;
    return { accessToken };
  }
}
