import { TokenSet } from 'openid-client';
import { ISession } from '../session/session';

export default function getSessionFromTokenSet(tokenSet: TokenSet): ISession {
  // Get the claims without any OIDC specific claim.
  const claims = tokenSet.claims();
  if (claims.aud) {
    delete claims.aud;
  }

  if (claims.exp) {
    delete claims.exp;
  }

  if (claims.iat) {
    delete claims.iat;
  }

  if (claims.iss) {
    delete claims.iss;
  }

  // Create the session.
  return {
    user: {
      ...claims
    },
    idToken: tokenSet.id_token,
    accessToken: tokenSet.access_token,
    accessTokenScope: tokenSet.scope,
    accessTokenExpiresAt: tokenSet.expires_at,
    refreshToken: tokenSet.refresh_token,
    createdAt: Date.now()
  };
}
