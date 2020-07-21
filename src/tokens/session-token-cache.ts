import { IncomingMessage, ServerResponse } from 'http';

import { ISessionStore } from '../session/store';
import AccessTokenError from './access-token-error';
import getSessionFromTokenSet from '../utils/session';
import { intersect, match } from '../utils/array';
import { IOidcClientFactory } from '../utils/oidc-client';
import { ITokenCache, AccessTokenRequest, AccessTokenResponse } from './token-cache';

export default class SessionTokenCache implements ITokenCache {
  private store: ISessionStore;

  private clientProvider: IOidcClientFactory;

  private req: IncomingMessage;

  private res: ServerResponse;

  constructor(store: ISessionStore, clientProvider: IOidcClientFactory, req: IncomingMessage, res: ServerResponse) {
    this.store = store;
    this.clientProvider = clientProvider;
    this.req = req;
    this.res = res;
  }

  async getAccessToken(accessTokenRequest?: AccessTokenRequest): Promise<AccessTokenResponse> {
    const session = await this.store.read(this.req);
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
      const client = await this.clientProvider();
      const tokenSet = await client.refresh(session.refreshToken);

      // Update the session.
      const newSession = getSessionFromTokenSet(tokenSet);
      await this.store.save(this.req, this.res, {
        ...newSession,
        refreshToken: newSession.refreshToken || session.refreshToken
      });

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
  }
}
