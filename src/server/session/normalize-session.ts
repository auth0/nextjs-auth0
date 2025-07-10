import { JWTDecryptResult } from "jose";

import { SessionData } from "../../types/index.js";

export const LEGACY_COOKIE_NAME = "appSession";

/**
 * Key-value store for the user's claims.
 */
interface LegacyClaims {
  [key: string]: any;
}

/**
 * The user's session.
 */
export class LegacySession {
  /**
   * Any of the claims from the `id_token`.
   */
  user: LegacyClaims;

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

  constructor(user: LegacyClaims) {
    this.user = user;
  }
}

/**
 * The legacy headers of the session.
 */
interface LegacyHeaders {
  /**
   * Timestamp (in secs) when the session was created.
   */
  iat: number;
  /**
   * Timestamp (in secs) when the session was last touched.
   */
  uat: number;
  /**
   * Timestamp (in secs) when the session expires.
   */
  exp: number;
}

export interface LegacySessionPayload {
  /**
   * The session header.
   */
  header: LegacyHeaders;

  /**
   * The session data.
   */
  data: LegacySession;
}

export function normalizeStatelessSession(
  sessionCookie: JWTDecryptResult<LegacySessionPayload | SessionData>
) {
  // if the session cookie has an `iat` claim in the protected header, it's a legacy cookie
  // otherwise, it's the new session cookie format and no transformation is needed
  if (sessionCookie.protectedHeader.iat) {
    const legacySession = sessionCookie as JWTDecryptResult<LegacySession>;
    return convertFromLegacy(
      legacySession.protectedHeader,
      legacySession.payload
    );
  }

  return sessionCookie.payload as SessionData;
}

export function normalizeStatefulSession(
  sessionData: SessionData | LegacySessionPayload
) {
  if ((sessionData.header as LegacyHeaders | undefined)?.iat) {
    const legacySession = sessionData as LegacySessionPayload;
    return convertFromLegacy(legacySession.header, legacySession.data);
  }

  return sessionData as SessionData;
}

function convertFromLegacy(
  header:
    | LegacyHeaders
    | JWTDecryptResult<LegacySessionPayload>["protectedHeader"],
  session: LegacySession
) {
  const userClaims = session.user as LegacyClaims;

  return {
    user: userClaims,
    tokenSet: {
      idToken: (session.idToken as string) ?? undefined,
      accessToken: (session.accessToken as string) ?? undefined,
      scope: session.accessTokenScope as string | undefined,
      refreshToken: session.refreshToken as string | undefined,
      expiresAt: session.accessTokenExpiresAt as number
    },
    internal: {
      sid: userClaims.sid,
      createdAt: header.iat
    }
  } as SessionData;
}
