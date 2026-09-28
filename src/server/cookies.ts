import type { NextResponse } from "next/server.js";
import {
  RequestCookie,
  RequestCookies,
  ResponseCookies
} from "@edge-runtime/cookies";
import { hkdf } from "@panva/hkdf";
import * as jose from "jose";

const ENC = "A256GCM";
const ALG = "dir";
const DIGEST = "sha256";
const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = "JWE CEK";

export async function encrypt(
  payload: jose.JWTPayload,
  secret: string,
  expiration: number,
  additionalHeaders?: {
    iat: number;
    uat: number;
    exp: number;
  }
) {
  const encryptionSecret = await hkdf(
    DIGEST,
    secret,
    "",
    ENCRYPTION_INFO,
    BYTE_LENGTH
  );

  const encryptedCookie = await new jose.EncryptJWT(payload)
    .setProtectedHeader({ enc: ENC, alg: ALG, ...additionalHeaders })
    .setExpirationTime(expiration)
    .encrypt(encryptionSecret);

  return encryptedCookie.toString();
}

export async function decrypt<T>(
  cookieValue: string,
  secret: string,
  options?: jose.JWTDecryptOptions,
  throwOnJWEErrors?: boolean
) {
  try {
    const encryptionSecret = await hkdf(
      DIGEST,
      secret,
      "",
      ENCRYPTION_INFO,
      BYTE_LENGTH
    );

    const cookie = await jose.jwtDecrypt<T>(cookieValue, encryptionSecret, {
      ...options,
      ...{ clockTolerance: 15 }
    });

    return cookie;
  } catch (e: any) {
    // When throwOnJWEErrors is true, throw the original error to preserve granular error codes
    if (throwOnJWEErrors) {
      throw e;
    }
    // When the JWE can not be decrypted or has expired, return null to indicate an invalid cookie and treat it as non-existent.
    if (
      e.code === "ERR_JWE_DECRYPTION_FAILED" ||
      e.code === "ERR_JWT_EXPIRED" ||
      e.code === "ERR_JWE_INVALID"
    ) {
      return null;
    }
    throw e;
  }
}

/**
 * Derive a signing key from a given secret.
 * This method is used solely to migrate signed, legacy cookies to the new encrypted cookie format (v4+).
 */
const signingSecret = (secret: string): Promise<Uint8Array> =>
  hkdf("sha256", secret, "", "JWS Cookie Signing", BYTE_LENGTH);

/**
 * Verify a signed cookie. If the cookie is valid, the value is returned. Otherwise, undefined is returned.
 * This method is used solely to migrate signed, legacy cookies to the new encrypted cookie format (v4+).
 */
export async function verifySigned(
  k: string,
  v: string,
  secret: string
): Promise<string | undefined> {
  if (!v) {
    return undefined;
  }
  const [value, signature] = v.split(".");
  const flattenedJWS = {
    protected: jose.base64url.encode(
      JSON.stringify({ alg: "HS256", b64: false, crit: ["b64"] })
    ),
    payload: `${k}=${value}`,
    signature
  };
  const key = await signingSecret(secret);

  try {
    await jose.flattenedVerify(flattenedJWS, key, {
      algorithms: ["HS256"]
    });
    return value;
  } catch (e) {
    return undefined;
  }
}

/**
 * Sign a cookie value using a secret.
 * This method is used solely to migrate signed, legacy cookies to the new encrypted cookie format (v4+).
 */
export async function sign(
  name: string,
  value: string,
  secret: string
): Promise<string> {
  const key = await signingSecret(secret);
  const { signature } = await new jose.FlattenedSign(
    new TextEncoder().encode(`${name}=${value}`)
  )
    .setProtectedHeader({ alg: "HS256", b64: false, crit: ["b64"] })
    .sign(key);
  return `${value}.${signature}`;
}

export interface CookieOptions {
  httpOnly: boolean;
  sameSite: "lax" | "strict" | "none";
  secure: boolean;
  path: string;
  maxAge?: number;
  domain?: string;
  transient?: boolean;
}

export type ReadonlyRequestCookies = Omit<
  RequestCookies,
  "set" | "clear" | "delete"
> &
  Pick<ResponseCookies, "set" | "delete">;
export { ResponseCookies };
export { RequestCookies };

// Chunked cookies Configuration
const MAX_CHUNK_SIZE = 3500; // Slightly under 4KB
const CHUNK_PREFIX = "__";
const CHUNK_INDEX_REGEX = new RegExp(`${CHUNK_PREFIX}(\\d+)$`);
const LEGACY_CHUNK_INDEX_REGEX = /\.(\d+)$/;
// Minimum deterministic sweep range for chunk cleanup. Cleanup uses
// `getClearUpTo`, which sweeps at least `__0..MAX_CHUNKS-1` (this constant) and
// also anything higher the current request's snapshot reveals. The deterministic
// minimum covers the concurrent-write case within this range: a tab that wrote a
// chunk absent from this request's stale snapshot is still cleaned. The snapshot
// extension covers the shrink case: a session that once grew past this range
// and later shrinks has its high-index chunks removed instead of orphaned.
// Values above `MAX_CHUNKS` written by a concurrent tab and absent from this
// snapshot are the residual case — the next write on this connection sees them
// and cleans up (self-healing after one bad response). 5 × 3500 = 17,500 bytes
// covers the typical session envelope; sessions larger than that surface the
// oversized-session warning in `stateless-session-store.ts`.
const MAX_CHUNKS = 5;

/**
 * Retrieves the index of a cookie based on its name.
 * Supports current format `{name}__{index}` and legacy format `{name}.{index}`.
 *
 * @param name - The name of the cookie.
 * @returns The index of the cookie. Returns undefined if no index is found.
 */
const getChunkedCookieIndex = (
  name: string,
  isLegacyCookie?: boolean
): number | undefined => {
  const match = isLegacyCookie
    ? LEGACY_CHUNK_INDEX_REGEX.exec(name)
    : CHUNK_INDEX_REGEX.exec(name);
  if (!match) {
    return undefined;
  }
  return parseInt(match[1], 10);
};

/**
 * Retrieves all cookies from the request that have names matching the exact
 * `{name}{CHUNK_PREFIX}{digits}` shape (or `{name}.{digits}` for the legacy
 * format). The regex is built once per shape at module load rather than per
 * call — `setChunkedCookie` runs on every authenticated request under rolling
 * sessions, so avoiding a fresh RegExp per call matters.
 *
 * @param reqCookies - The cookies from the request.
 * @param name - The base name of the cookies to retrieve.
 * @returns An array of cookies matching the chunked-cookie shape.
 */
const getAllChunkedCookies = (
  reqCookies: RequestCookies,
  name: string,
  isLegacyCookie?: boolean
): RequestCookie[] => {
  const regex = isLegacyCookie
    ? getLegacyChunkedCookieRegex(name)
    : getChunkedCookieRegex(name);
  return reqCookies.getAll().filter((cookie) => regex.test(cookie.name));
};

// Per-name regex caches, populated on first use. Prevents rebuilding the same
// RegExp on every hot-path call. Names are bounded (session, legacy session,
// __FC cookies), so unbounded growth is not a concern.
const chunkedCookieRegexCache = new Map<string, RegExp>();
const legacyChunkedCookieRegexCache = new Map<string, RegExp>();

const getChunkedCookieRegex = (name: string): RegExp => {
  const cached = chunkedCookieRegexCache.get(name);
  if (cached) return cached;
  const regex = new RegExp(`^${name}${CHUNK_PREFIX}\\d+$`);
  chunkedCookieRegexCache.set(name, regex);
  return regex;
};

const getLegacyChunkedCookieRegex = (name: string): RegExp => {
  const cached = legacyChunkedCookieRegexCache.get(name);
  if (cached) return cached;
  const regex = new RegExp(`^${name}${LEGACY_CHUNK_INDEX_REGEX.source}$`);
  legacyChunkedCookieRegexCache.set(name, regex);
  return regex;
};

/**
 * Returns the exclusive upper bound for chunk-cleanup loops: `max(MAX_CHUNKS,
 * highestSeenIndex + 1)`. Guarantees the deterministic `__0..MAX_CHUNKS-1`
 * sweep (which covers concurrent-tab writes below `MAX_CHUNKS` that this
 * request's snapshot missed), while also clearing anything the current
 * snapshot reveals above that range — so a session that once grew past
 * `MAX_CHUNKS` and later shrinks does not leave orphaned high-index chunks.
 *
 * Residual case: a concurrent tab that wrote `__session__N` with `N >=
 * MAX_CHUNKS`, absent from THIS request's snapshot, is not cleared here.
 * That single request's read returns `undefined` for the session. The next
 * write on this connection sees `__N` in its snapshot and cleans it up
 * (self-healing). Bounded to at most one bad response per orphan.
 */
const getClearUpTo = (reqCookies: RequestCookies, name: string): number => {
  let highestSeen = -1;
  for (const cookie of getAllChunkedCookies(reqCookies, name)) {
    const idx = getChunkedCookieIndex(cookie.name);
    if (idx !== undefined && idx > highestSeen) highestSeen = idx;
  }
  return Math.max(MAX_CHUNKS, highestSeen + 1);
};

/**
 * Sets a cookie with the given name and value, splitting it into chunks if necessary.
 *
 * If the value exceeds the maximum chunk size, it will be split into multiple cookies
 * with names suffixed by a chunk index.
 *
 * @param name - The name of the cookie.
 * @param value - The value to be stored in the cookie.
 * @param options - Options for setting the cookie.
 * @param reqCookies - The request cookies object, used to enable read-after-write in the same request for middleware.
 * @param resCookies - The response cookies object, used to set the cookies in the response.
 * @returns The total encoded `name=value` byte size of the cookie(s) written —
 *          lets callers check against header-size limits without re-scanning
 *          `resCookies` afterwards.
 */
export function setChunkedCookie(
  name: string,
  value: string,
  options: CookieOptions,
  reqCookies: RequestCookies,
  resCookies: ResponseCookies
): number {
  const { transient, ...restOptions } = options;
  const finalOptions = { ...restOptions };

  if (transient) {
    delete finalOptions.maxAge;
  }

  const encoder = new TextEncoder();
  const sizeOf = (cookieName: string, cookieValue: string) =>
    encoder.encode(`${cookieName}=${cookieValue}`).length;

  const valueBytes = encoder.encode(value).length;

  // Hoist the delete-options object out of the loops. `setChunkedCookie` runs
  // on every authenticated request under rolling sessions, so allocating one
  // object per iteration adds up.
  const deleteOptions = {
    path: finalOptions.path,
    domain: finalOptions.domain,
    secure: finalOptions.secure,
    sameSite: finalOptions.sameSite,
    httpOnly: finalOptions.httpOnly
  };

  // If value fits in a single cookie, set it directly
  if (valueBytes <= MAX_CHUNK_SIZE) {
    resCookies.set(name, value, finalOptions);
    // to enable read-after-write in the same request for middleware
    reqCookies.set(name, value);

    // When we are writing a non-chunked cookie, remove any previously stored
    // chunks for this cookie name. Sweep at least `__0..MAX_CHUNKS-1` (covers
    // concurrent-tab writes below MAX_CHUNKS not in this snapshot) and also
    // anything higher the snapshot reveals (covers sessions that once grew past
    // MAX_CHUNKS). The browser ignores deletions for cookies that do not exist.
    const clearUpTo = getClearUpTo(reqCookies, name);
    for (let i = 0; i < clearUpTo; i++) {
      const chunkName = `${name}${CHUNK_PREFIX}${i}`;
      deleteCookie(resCookies, chunkName, deleteOptions);
      reqCookies.delete(chunkName);
    }

    return sizeOf(name, value);
  }

  // Split value into chunks
  let position = 0;
  let chunkIndex = 0;
  let totalBytes = 0;

  while (position < value.length) {
    const chunk = value.slice(position, position + MAX_CHUNK_SIZE);
    const chunkName = `${name}${CHUNK_PREFIX}${chunkIndex}`;

    resCookies.set(chunkName, chunk, finalOptions);
    // to enable read-after-write in the same request for middleware
    reqCookies.set(chunkName, chunk);
    totalBytes += sizeOf(chunkName, chunk);
    position += MAX_CHUNK_SIZE;
    chunkIndex++;
  }

  // Clear any now-unused higher-index chunks. Sweep at least up to
  // `MAX_CHUNKS-1` (covers concurrent-tab writes below MAX_CHUNKS not in this
  // snapshot) and also anything higher the snapshot reveals (covers sessions
  // that once grew past MAX_CHUNKS). The browser ignores deletions for absent
  // cookies.
  const clearUpTo = getClearUpTo(reqCookies, name);
  for (let i = chunkIndex; i < clearUpTo; i++) {
    const chunkName = `${name}${CHUNK_PREFIX}${i}`;
    deleteCookie(resCookies, chunkName, deleteOptions);
    reqCookies.delete(chunkName);
  }

  // When we have written chunked cookies, we should remove the non-chunked cookie
  deleteCookie(resCookies, name, deleteOptions);
  reqCookies.delete(name);

  return totalBytes;
}

/**
 * Retrieves a chunked cookie by its name from the request cookies.
 * If a regular cookie with the given name exists, it returns its value.
 * Otherwise, it attempts to retrieve and combine all chunks of the cookie.
 *
 * @param name - The name of the cookie to retrieve.
 * @param reqCookies - The request cookies object.
 * @returns The combined value of the chunked cookie, or `undefined` if the cookie does not exist or is incomplete.
 */
export function getChunkedCookie(
  name: string,
  reqCookies: RequestCookies,
  isLegacyCookie?: boolean
): string | undefined {
  // Check if regular cookie exists
  const cookie = reqCookies.get(name);
  if (cookie?.value) {
    // If the base cookie exists, return its value (handles non-chunked case)
    return cookie.value;
  }

  const chunks = getAllChunkedCookies(reqCookies, name, isLegacyCookie).sort(
    // Extract index from cookie name and sort numerically
    (first, second) => {
      return (
        getChunkedCookieIndex(first.name, isLegacyCookie)! -
        getChunkedCookieIndex(second.name, isLegacyCookie)!
      );
    }
  );

  if (chunks.length === 0) {
    return undefined;
  }

  // Validate sequence integrity - check for missing chunks
  const highestIndex = getChunkedCookieIndex(
    chunks[chunks.length - 1].name,
    isLegacyCookie
  )!;
  if (chunks.length !== highestIndex + 1) {
    console.warn(
      `Incomplete chunked cookie '${name}': Found ${chunks.length} chunks, expected ${highestIndex + 1}`
    );
    return undefined;
  }

  // Combine all chunks
  return chunks.map((c) => c.value).join("");
}

/**
 * Deletes a chunked cookie and all its associated chunks from the response cookies.
 *
 * @param name - The name of the main cookie to delete.
 * @param reqCookies - The request cookies object containing all cookies from the request.
 * @param resCookies - The response cookies object to manipulate the cookies in the response.
 * @param isLegacyCookie - Whether to handle legacy cookie format.
 * @param options - Options for cookie deletion including domain and path.
 */
export function deleteChunkedCookie(
  name: string,
  reqCookies: RequestCookies,
  resCookies: ResponseCookies,
  isLegacyCookie?: boolean,
  options?: Pick<CookieOptions, "domain" | "path"> &
    Partial<Pick<CookieOptions, "secure" | "sameSite" | "httpOnly">>
): void {
  // Delete main cookie
  deleteCookie(resCookies, name, options);

  if (isLegacyCookie) {
    // Legacy `{name}.{index}` chunks are no longer written, so their count is
    // whatever a prior SDK version left behind — scan the request to find them.
    getAllChunkedCookies(reqCookies, name, isLegacyCookie).forEach((cookie) => {
      deleteCookie(resCookies, cookie.name, options);
    });
    return;
  }

  // Sweep at least `__0..MAX_CHUNKS-1` (covers concurrent-tab writes not in
  // this snapshot) and also anything higher the snapshot reveals (covers
  // sessions that once grew past MAX_CHUNKS). The browser ignores deletions
  // for absent cookies.
  const clearUpTo = getClearUpTo(reqCookies, name);
  for (let i = 0; i < clearUpTo; i++) {
    deleteCookie(resCookies, `${name}${CHUNK_PREFIX}${i}`, options);
  }
}

/**
 * Unconditionally adds strict cache-control headers to the response.
 *
 * This ensures the response is not cached by CDNs or other shared caches.
 * It is now the caller's responsibility to decide when to call this function.
 *
 * Usage:
 * Call this function whenever a `Set-Cookie` header is being written
 * for session management or any other sensitive data that must not be cached.
 */
export function addCacheControlHeadersForSession(res: NextResponse): void {
  res.headers.set(
    "Cache-Control",
    "private, no-cache, no-store, must-revalidate, max-age=0"
  );
  res.headers.set("Pragma", "no-cache");
  res.headers.set("Expires", "0");
}

/**
 * Deletes a cookie from the response with optional domain, path, and security attribute specifications.
 *
 * Security attributes (Secure, SameSite, HttpOnly) must mirror those used when the cookie was originally
 * set. Browsers require matching security attributes on deletion to correctly identify and remove the
 * cookie, especially for Secure cookies under Scheme-Bound Cookie enforcement (Chromium 124+).
 *
 * @param resCookies - The response cookies object to manipulate.
 * @param name - The name of the cookie to delete.
 * @param options - Optional domain, path, and security settings for cookie deletion.
 */
export function deleteCookie(
  resCookies: ResponseCookies,
  name: string,
  options?: Pick<CookieOptions, "domain" | "path"> &
    Partial<Pick<CookieOptions, "secure" | "sameSite" | "httpOnly">>
) {
  const deleteOptions: {
    maxAge: number;
    domain?: string;
    path?: string;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
    httpOnly?: boolean;
  } = {
    maxAge: 0 // Ensure the cookie is deleted immediately
  };

  if (options?.domain) {
    deleteOptions.domain = options.domain;
  }

  if (options?.path) {
    deleteOptions.path = options.path;
  }

  if (options?.secure !== undefined) {
    deleteOptions.secure = options.secure;
  }

  if (options?.sameSite !== undefined) {
    deleteOptions.sameSite = options.sameSite;
  }

  if (options?.httpOnly !== undefined) {
    deleteOptions.httpOnly = options.httpOnly;
  }

  resCookies.set(name, "", deleteOptions);
}
