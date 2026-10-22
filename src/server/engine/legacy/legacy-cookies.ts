import type { CookieSerializeOptions } from "@auth0/auth0-server-js";
import { decodeProtectedHeader } from "jose";

import type { ConnectionTokenSet, SessionData } from "../../../types/index.js";
import {
  getAllChunkedCookies,
  getChunkedCookie
} from "../../cookies/chunks.js";
import { decrypt, verifySigned } from "../../cookies/encryption.js";
import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import {
  LEGACY_COOKIE_NAME,
  LegacySessionPayload,
  normalizeStatelessSession
} from "./normalize-session.js";

/**
 * Old-format cookies written by v4 and v3 of this SDK.
 *
 * Read here so that upgrading does not log anyone out, and deleted by exact name once the
 * session has been saved in the engine format. Nothing here writes the old format.
 *
 * Remove once old cookies have expired (future major).
 */

const CONNECTION_TOKEN_SET_COOKIE_REGEX = /^__FC_\d+$/;

type RequestCookieSource = CookieContext["reqCookies"];

/**
 * Reads a v4 (`name` / `name__N`) or v3 (`appSession` / `appSession.N`) stateless session,
 * plus any v4 `__FC_<n>` connection token set cookies. Returns `null` when nothing readable is
 * present. Same order and checks as `StatelessSessionStore.get` on `main`.
 */
export async function readLegacySession(
  reqCookies: RequestCookieSource,
  sessionName: string,
  secret: string
): Promise<SessionData | null> {
  const cookieValue =
    getChunkedCookie(sessionName, reqCookies) ??
    getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true);

  if (!cookieValue) {
    return null;
  }

  const originalSession = await decrypt<SessionData | LegacySessionPayload>(
    cookieValue,
    secret
  );

  if (!originalSession) {
    return null;
  }

  const connectionTokenSets: ConnectionTokenSet[] = [];
  for (const cookie of reqCookies.getAll()) {
    if (!CONNECTION_TOKEN_SET_COOKIE_REGEX.test(cookie.name)) {
      continue;
    }
    const decryptedCookie = await decrypt<ConnectionTokenSet>(
      cookie.value,
      secret
    );
    if (decryptedCookie) {
      connectionTokenSets.push(decryptedCookie.payload);
    }
  }

  return {
    ...normalizeStatelessSession(originalSession),
    ...(connectionTokenSets.length ? { connectionTokenSets } : {})
  };
}

/**
 * Reads the session ID from a v4 stateful cookie value (JWE `{ id }`). Returns `null` when the
 * value cannot be decrypted. Same checks as `StatefulSessionStore.get` on `main`.
 */
export async function decryptLegacySessionId(
  value: string,
  secret: string
): Promise<string | null> {
  try {
    const sessionCookie = await decrypt<{ id: string }>(
      value,
      secret,
      undefined,
      true
    );
    return sessionCookie?.payload.id ?? null;
  } catch {
    return null;
  }
}

/**
 * Reads the session ID from a v3 signed stateful cookie, under the session name or `appSession`.
 * Returns `null` when no ID can be recovered, including when the cookie is a JWE (v4 or engine
 * format, read through `decryptLegacySessionId` or the engine). Same checks as
 * `StatefulSessionStore.get` on `main`.
 */
export async function readV3SessionId(
  reqCookies: RequestCookieSource,
  sessionName: string,
  secret: string
): Promise<string | null> {
  const cookie =
    reqCookies.get(sessionName) || reqCookies.get(LEGACY_COOKIE_NAME);

  if (!cookie?.value || isCompactJwe(cookie.value)) {
    return null;
  }

  return (await verifySigned(cookie.name, cookie.value, secret)) ?? null;
}

/**
 * Whether a cookie value is a v3 or v4 JWE: same compact format as the engine's, but without `kid`
 * in the header. The engine throws a plain `Error` on these instead of returning no session.
 */
export function isLegacyJwe(value: string): boolean {
  try {
    return !decodeProtectedHeader(value).kid;
  } catch {
    // Not a JWE (for example a v3 signed value).
    return false;
  }
}

// A compact JWE has five dot-separated parts; a v3 signed value is `value.signature`.
function isCompactJwe(value: string): boolean {
  return value.split(".").length === 5;
}

/**
 * Deletes every old-format cookie present in the request, by exact name.
 *
 * - stateless: `name`, `name__N`, `__FC_<n>`
 * - both modes: `appSession`, `appSession.N` (skipped when the session name is `appSession`)
 *
 * In stateful mode the engine writes the session name itself, so it is never deleted here.
 */
export function deleteLegacyCookies(
  handler: NextCookieHandler,
  ctx: CookieContext,
  {
    sessionName,
    stateful,
    deleteOptions
  }: {
    sessionName: string;
    stateful: boolean;
    deleteOptions: CookieSerializeOptions;
  }
): void {
  const { reqCookies } = ctx;
  const names: string[] = [];

  if (!stateful) {
    if (reqCookies.has(sessionName)) {
      names.push(sessionName);
    }
    for (const cookie of getAllChunkedCookies(reqCookies, sessionName)) {
      names.push(cookie.name);
    }
    for (const cookie of reqCookies.getAll()) {
      if (CONNECTION_TOKEN_SET_COOKIE_REGEX.test(cookie.name)) {
        names.push(cookie.name);
      }
    }
  }

  if (sessionName !== LEGACY_COOKIE_NAME) {
    if (reqCookies.has(LEGACY_COOKIE_NAME)) {
      names.push(LEGACY_COOKIE_NAME);
    }
    for (const cookie of getAllChunkedCookies(
      reqCookies,
      LEGACY_COOKIE_NAME,
      true
    )) {
      names.push(cookie.name);
    }
  }

  for (const name of names) {
    handler.deleteCookie(name, ctx, deleteOptions);
  }
}

/**
 * Deletes `main`'s anonymous session cookies present in the request, by exact name: `name` and
 * `name__N`. The engine's anonymous store writes `name.N`, so these are never its own, and nothing
 * else removes them. They are not read either (the visitor gets a new anonymous session once).
 */
export function deleteLegacyAnonymousCookies(
  handler: NextCookieHandler,
  ctx: CookieContext,
  {
    name,
    deleteOptions
  }: { name: string; deleteOptions: CookieSerializeOptions }
): void {
  const { reqCookies } = ctx;
  const names: string[] = [];

  if (reqCookies.has(name)) {
    names.push(name);
  }
  for (const cookie of getAllChunkedCookies(reqCookies, name)) {
    names.push(cookie.name);
  }

  for (const cookieName of names) {
    handler.deleteCookie(cookieName, ctx, deleteOptions);
  }
}
