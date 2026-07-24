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
 * 2. Session ID token (must be unexpired — server rejects expired actor tokens;
 *    this function does NOT refresh it, it fails when the token is already expired)
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
 * Builds the target login URL carrying the STT (and optional `organization`) as
 * query parameters. Pure string builder — no network call, nothing persisted.
 *
 * Throws `CustomTokenExchangeError(EXCHANGE_FAILED)` if `targetLoginUrl` is not a
 * valid absolute `http`/`https` URL. `targetLoginUrl` must be a trusted, app-controlled value.
 *
 * Shared by both the core `AuthClient` and the `Auth0Client` wrapper (including its
 * resolver-mode fallback) so the STT query-param logic and URL guard live in one place.
 */
export function buildSessionTransferRedirectUrl(
  targetLoginUrl: string,
  sessionTransferToken: string,
  opts?: { organization?: string }
): string {
  let url: URL;
  try {
    url = new URL(targetLoginUrl);
  } catch {
    throw new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
      `Invalid targetLoginUrl: "${targetLoginUrl}" is not an absolute URL. ` +
        "Pass a trusted, app-controlled absolute login URL (e.g. https://app.example.com/auth/login)."
    );
  }
  const isLocalhost =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost)) {
    throw new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
      `Invalid targetLoginUrl: "${targetLoginUrl}" must use https (or http for localhost).`
    );
  }
  url.searchParams.set("session_transfer_token", sessionTransferToken);
  if (opts?.organization) {
    url.searchParams.set("organization", opts.organization);
  }
  return url.toString();
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
    expiresIn:
      raw.expires_in !== undefined ? Number(raw.expires_in) : undefined,
    tokenType: raw.token_type
  };
}

/**
 * Maps a server STT failure to a typed `CustomTokenExchangeErrorCode`, keyed off the
 * machine-readable `error` code only.
 *
 * Per the SDK requirements, the SDK does NOT match against `error_description` text to
 * remap failures. Today Auth0 returns these failures with a generic `error`
 * (`invalid_request`) and the detail in `error_description`, so this returns `null` and
 * the caller surfaces the raw `error`/`error_description` as `EXCHANGE_FAILED`. These
 * named constants exist for documentation and for the day the platform returns a
 * machine-readable code (`setactor_required` / `session_transfer_disabled`), at which
 * point this mapping starts firing without any further change.
 */
export function mapSttServerError(
  errorCode: string
): CustomTokenExchangeErrorCode | null {
  const code = errorCode.toLowerCase();
  if (code === "setactor_required") {
    return CustomTokenExchangeErrorCode.SETACTOR_REQUIRED;
  }
  if (code === "session_transfer_disabled") {
    return CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED;
  }
  return null;
}
