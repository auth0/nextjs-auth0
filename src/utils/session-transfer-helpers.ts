import * as jose from "jose";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "../errors/oauth-errors.js";
import {
  SessionData,
  SessionTransferTokenResult,
  TOKEN_TYPES
} from "../types/index.js";

/**
 * Builds the `audience` value for a Session Transfer Token exchange.
 * The audience is always `urn:{domain}:session_transfer` — the switch that
 * makes Auth0 return an STT instead of a regular access token.
 *
 * Uses the SDK's effective domain so that Multiple Custom Domain tenants
 * get the correct per-domain audience rather than the static configured domain.
 */
export function buildSessionTransferAudience(domain: string): string {
  return `urn:${domain}:session_transfer`;
}

/**
 * Resolves the actor token pair for an STT exchange.
 *
 * Precedence:
 * 1. Explicit `actor` passed by the caller
 * 2. Session ID token (must be unexpired — server rejects expired actor tokens)
 * 3. `ACTOR_UNAVAILABLE` thrown client-side
 *
 * An actor is mandatory for an STT. Without one the exchange fails server-side
 * with `setActor is required`, and without a recorded actor it is not auditable
 * impersonation.
 */
export function resolveActorFromSession(
  session: SessionData | null,
  explicitActor?: { token: string; type: TOKEN_TYPES | string }
): [CustomTokenExchangeError, null] | [null, { token: string; type: string }] {
  if (explicitActor) {
    if (!explicitActor.token || explicitActor.token.trim() === "") {
      return [
        new CustomTokenExchangeError(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE,
          "The explicit actor token is empty."
        ),
        null
      ];
    }
    return [null, { token: explicitActor.token, type: explicitActor.type }];
  }

  const idToken = session?.tokenSet?.idToken;
  if (!idToken) {
    return [
      new CustomTokenExchangeError(
        CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE,
        "No actor could be resolved: no explicit actor was provided and the agent session has no ID token. " +
          "Ensure the agent is authenticated, or pass an explicit actor."
      ),
      null
    ];
  }

  // Guard against expired ID tokens — the server validates exp on the actor_token
  // and rejects with "Invalid actor token: 'exp' claim timestamp check failed".
  try {
    const { exp } = jose.decodeJwt(idToken);
    if (typeof exp === "number" && exp < Math.floor(Date.now() / 1000)) {
      return [
        new CustomTokenExchangeError(
          CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE,
          "The agent session ID token has expired. Refresh the session before requesting a Session Transfer Token, " +
            "or pass a fresh actor token explicitly."
        ),
        null
      ];
    }
  } catch {
    return [
      new CustomTokenExchangeError(
        CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE,
        "The agent session ID token could not be decoded."
      ),
      null
    ];
  }

  return [null, { token: idToken, type: TOKEN_TYPES.ID_TOKEN }];
}

/**
 * Maps the raw token endpoint response to a `SessionTransferTokenResult`.
 *
 * The server signals an STT via `issued_token_type`; the `access_token` field
 * holds the opaque STT rather than a usable API bearer token.
 */
export function parseSessionTransferTokenResponse(raw: {
  access_token: string;
  issued_token_type: string;
  expires_in?: number;
  token_type?: string;
}): SessionTransferTokenResult {
  return {
    sessionTransferToken: raw.access_token,
    issuedTokenType: raw.issued_token_type,
    expiresIn: Number(raw.expires_in ?? 60),
    tokenType: raw.token_type
  };
}

/**
 * Maps a server 400 error code to a typed `CustomTokenExchangeErrorCode` for STT failures.
 * Returns `null` when the error code is not STT-specific (caller should fall through to EXCHANGE_FAILED).
 */
export function mapSttServerError(
  errorCode: string
): CustomTokenExchangeErrorCode | null {
  if (
    errorCode === "setactor_required" ||
    errorCode.toLowerCase().includes("setactor")
  ) {
    return CustomTokenExchangeErrorCode.SETACTOR_REQUIRED;
  }
  if (
    errorCode === "session_transfer_disabled" ||
    errorCode.toLowerCase().includes("session_transfer")
  ) {
    return CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED;
  }
  return null;
}
