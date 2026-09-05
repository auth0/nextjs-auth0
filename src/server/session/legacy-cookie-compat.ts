import type { StateData } from "@auth0/auth0-server-js";

import type { SessionData } from "../../types/index.js";
import {
  decrypt as decryptV4,
  deleteChunkedCookie,
  getChunkedCookie,
  RequestCookies,
  ResponseCookies,
  verifySigned
} from "../cookies/index.js";
import {
  LEGACY_COOKIE_NAME,
  LegacySessionPayload,
  normalizeStatelessSession
} from "./normalize-session.js";
import { sessionDataToStateData } from "./session-mapper.js";

/**
 * Cookie attributes used when deleting old-format cookies. Mirrors the subset
 * accepted by `deleteChunkedCookie` / `deleteCookie`. Browsers require the
 * delete to carry the same `domain` / `path` / `secure` / `sameSite` / `httpOnly`
 * the cookie was written with, otherwise the deletion is ignored.
 */
export type LegacyCookieDeleteOptions = {
  domain?: string;
  // Required: browsers match deletions on `path`, and `deleteChunkedCookie` /
  // `deleteCookie` type it as required (from `CookieOptions.path`).
  path: string;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
  httpOnly?: boolean;
};

// A caller-supplied override where every attribute is optional; merged over the
// engine cookie config by `buildLegacyDeleteOptions`.
export type LegacyCookieOverrides = Partial<LegacyCookieDeleteOptions>;

/**
 * Builds the delete/attribute options for old-format cleanup.
 *
 * The engine's `SessionCookieOptions` carries `path` / `secure` / `sameSite`
 * only (no `domain`, `httpOnly` is always `true`). A `domain`-configured
 * consumer's legacy cookies can only be deleted when the delete also carries
 * that `domain`; the engine store config cannot supply it, so it is threaded in
 * via `override` (from nextjs-auth0's own `CookieOptions`) during ServerClient
 * wiring. Without an override we fall back to the engine cookie config.
 */
export function buildLegacyDeleteOptions(
  cookie?: {
    path?: string;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
  },
  override?: LegacyCookieOverrides
): LegacyCookieDeleteOptions {
  return {
    path: override?.path ?? cookie?.path ?? "/",
    domain: override?.domain,
    secure: override?.secure ?? cookie?.secure ?? true,
    sameSite: override?.sameSite ?? cookie?.sameSite ?? "lax",
    httpOnly: override?.httpOnly ?? true
  };
}

// `EncryptedStoreOptions.secret` is `string | string[]` (secret rotation). The
// nextjs-auth0 legacy crypto helpers take a single secret string, so we try
// each in order, exactly as the engine tries each for decryption.
function toSecrets(secret: string | string[]): string[] {
  return Array.isArray(secret) ? secret : [secret];
}

/**
 * Reads a legacy STATELESS session cookie (v4 `__session` / `name__N`, A256GCM,
 * or v3 `appSession` / `appSession.N`) and maps it into the engine's
 * `StateData`. Returns `undefined` when no readable legacy cookie is present.
 * Never throws on unreadable data.
 *
 * This is the migration read path that sits ABOVE the engine's native-only
 * `get()`/`decrypt()`: cookie assembly (which name, how chunks are suffixed) and
 * payload-shape normalization are format-specific and cannot be expressed by a
 * `decrypt`-only override.
 */
export async function readLegacyStatelessStateData(
  reqCookies: RequestCookies,
  sessionCookieName: string,
  secret: string | string[]
): Promise<StateData | undefined> {
  // v4 first (bare `__session` or `name__N` chunks), then v3 `appSession`
  // (bare or `appSession.N`). Mirrors today's `StatelessSessionStore.get`.
  const cookieValue =
    getChunkedCookie(sessionCookieName, reqCookies) ??
    getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true);

  if (!cookieValue) {
    return undefined;
  }

  for (const s of toSecrets(secret)) {
    const originalSession = await decryptV4<SessionData | LegacySessionPayload>(
      cookieValue,
      s
    );

    if (originalSession) {
      // `normalizeStatelessSession` distinguishes v3 vs v4 by the protected
      // header `iat` and returns a v4-shaped `SessionData`; the mapper lifts it
      // into `StateData`. Connection token sets (`__FC_*`) are intentionally not
      // read here: they remain owned by the connected-accounts code.
      const sessionData = normalizeStatelessSession(originalSession);
      return sessionDataToStateData(sessionData);
    }
  }

  return undefined;
}

/**
 * Resolves the STATEFUL session ID from a legacy cookie. Tries the v4 JWE `{id}`
 * payload first, then the v3 HMAC-signed value, across both the configured
 * session cookie name and the v3 `appSession` name. Returns `undefined` when no
 * legacy session ID can be recovered. Never throws.
 *
 * Mirrors today's `StatefulSessionStore.get` ID-extraction logic.
 */
export async function readLegacyStatefulSessionId(
  reqCookies: RequestCookies,
  sessionCookieName: string,
  secret: string | string[]
): Promise<string | undefined> {
  const cookie =
    reqCookies.get(sessionCookieName) ?? reqCookies.get(LEGACY_COOKIE_NAME);

  if (!cookie?.value) {
    return undefined;
  }

  for (const s of toSecrets(secret)) {
    try {
      // `throwOnJWEErrors: true` so an invalid JWE (possibly a v3 signed value)
      // surfaces as ERR_JWE_INVALID and we can fall back to signature checking,
      // rather than being swallowed as `null`.
      const sessionCookie = await decryptV4<{ id: string }>(
        cookie.value,
        s,
        undefined,
        true
      );

      if (sessionCookie) {
        return sessionCookie.payload.id;
      }
    } catch (e: unknown) {
      if ((e as { code?: string })?.code === "ERR_JWE_INVALID") {
        const legacySessionId = await verifySigned(
          cookie.name,
          cookie.value,
          s
        );
        if (legacySessionId) {
          return legacySessionId;
        }
      }
      // Any other error (e.g. expired) -> treat as unreadable for this secret.
    }
  }

  return undefined;
}

/**
 * Deletes the v3 `appSession` cookie (and its `appSession.N` chunks) when
 * present. No-op when neither exists. Shared by the stateless and stateful
 * store subclasses for old-format cleanup on write/delete.
 */
export function cleanupLegacyStatelessCookies(
  reqCookies: RequestCookies,
  resCookies: ResponseCookies,
  deleteOptions: LegacyCookieDeleteOptions
): void {
  if (getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true)) {
    deleteChunkedCookie(
      LEGACY_COOKIE_NAME,
      reqCookies,
      resCookies,
      true,
      deleteOptions
    );
  }
}
