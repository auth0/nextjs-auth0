import type { RequestCookie, RequestCookies } from "@edge-runtime/cookies";

/** Read access shared by `RequestCookies` and the `cookies()` store from `next/headers`. */
type ChunkSource = Pick<RequestCookies, "get" | "getAll">;

const CHUNK_PREFIX = "__";
const CHUNK_INDEX_REGEX = new RegExp(`${CHUNK_PREFIX}(\\d+)$`);
const LEGACY_CHUNK_INDEX_REGEX = /\.(\d+)$/;

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
 * format). The regex is built once per name and cached.
 *
 * @param reqCookies - The cookies from the request.
 * @param name - The base name of the cookies to retrieve.
 * @returns An array of cookies matching the chunked-cookie shape.
 */
export const getAllChunkedCookies = (
  reqCookies: ChunkSource,
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
  reqCookies: ChunkSource,
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
