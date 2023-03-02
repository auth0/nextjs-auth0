import type { TokenSet } from 'openid-client';
import { Config } from '../auth0-session';
import { NextConfig } from '../config';

/**
 * Key-value store for the user's claims.
 *
 * @category Server
 */
export interface Claims {
  [key: string]: any;
}

/**
 * The user's session.
 *
 * @category Server
 */
export default class Session {
  /**
   * Any of the claims from the `id_token`.
   */
  user: Claims;

  /**
   * The ID token.
   */
  idToken?: string | undefined;

  /**
   * The access token.
   */
  accessToken?: string | undefined;

  /**
   * The access token scopes.
   */
  accessTokenScope?: string | undefined;

  /**
   * The expiration of the access token.
   */
  accessTokenExpiresAt?: number;

  /**
   * The refresh token, which is used to request a new access token.
   *
   * **IMPORTANT** You need to request the `offline_access` scope on login to get a refresh token
   * from Auth0.
   */
  refreshToken?: string | undefined;

  [key: string]: any;

  constructor(user: Claims) {
    this.user = user;
  }
}

/**
 * @ignore
 */
export function fromTokenSet(tokenSet: TokenSet, config: Config | NextConfig): Session {
  // Get the claims without any OIDC-specific claim.
  const claims = tokenSet.claims();
  config.identityClaimFilter.forEach((claim) => {
    delete claims[claim];
  });

  const { id_token, access_token, scope, expires_at, refresh_token, ...remainder } = tokenSet;
  const storeIDToken = config.session.storeIDToken;

  return Object.assign(
    new Session({ ...claims }),
    {
      accessToken: access_token,
      accessTokenScope: scope,
      accessTokenExpiresAt: expires_at,
      refreshToken: refresh_token,
      ...(storeIDToken && { idToken: id_token })
    },
    remainder
  );
}

/**
 * @ignore
 */
export function fromJson(json: { [key: string]: any } | undefined): Session | null {
  if (!json) {
    return null;
  }
  return Object.assign(new Session({ ...json.user }), json);
}
