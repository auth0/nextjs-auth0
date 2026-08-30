import type { NextResponse } from "next/server.js";
import {
  RequestCookie,
  RequestCookies,
  ResponseCookies
} from "@edge-runtime/cookies";

import type { CookieOptions } from "./index.js";

// Chunked cookies Configuration
const MAX_CHUNK_SIZE = 3500; // Slightly under 4KB
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
 * Retrieves all cookies from the request that have names starting with a specific prefix.
 *
 * @param reqCookies - The cookies from the request.
 * @param name - The base name of the cookies to retrieve.
 * @returns An array of cookies that have names starting with the specified prefix.
 */
const getAllChunkedCookies = (
  reqCookies: RequestCookies,
  name: string,
  isLegacyCookie?: boolean
): RequestCookie[] => {
  const chunkedCookieRegex = new RegExp(
    isLegacyCookie
      ? `^${name}${LEGACY_CHUNK_INDEX_REGEX.source}$`
      : `^${name}${CHUNK_PREFIX}\\d+$`
  );
  return reqCookies
    .getAll()
    .filter((cookie) => chunkedCookieRegex.test(cookie.name));
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
 */
export function setChunkedCookie(
  name: string,
  value: string,
  options: CookieOptions,
  reqCookies: RequestCookies,
  resCookies: ResponseCookies
): void {
  const { transient, ...restOptions } = options;
  const finalOptions = { ...restOptions };

  if (transient) {
    delete finalOptions.maxAge;
  }

  const valueBytes = new TextEncoder().encode(value).length;

  // If value fits in a single cookie, set it directly
  if (valueBytes <= MAX_CHUNK_SIZE) {
    resCookies.set(name, value, finalOptions);
    // to enable read-after-write in the same request for middleware
    reqCookies.set(name, value);

    // When we are writing a non-chunked cookie, we should remove the chunked cookies
    // Remove any previously stored chunks for this cookie name
    getAllChunkedCookies(reqCookies, name).forEach((cookieChunk) => {
      deleteCookie(resCookies, cookieChunk.name, {
        path: finalOptions.path,
        domain: finalOptions.domain,
        secure: finalOptions.secure,
        sameSite: finalOptions.sameSite,
        httpOnly: finalOptions.httpOnly
      });
      reqCookies.delete(cookieChunk.name);
    });

    return;
  }

  // Split value into chunks
  let position = 0;
  let chunkIndex = 0;

  while (position < value.length) {
    const chunk = value.slice(position, position + MAX_CHUNK_SIZE);
    const chunkName = `${name}${CHUNK_PREFIX}${chunkIndex}`;

    resCookies.set(chunkName, chunk, finalOptions);
    // to enable read-after-write in the same request for middleware
    reqCookies.set(chunkName, chunk);
    position += MAX_CHUNK_SIZE;
    chunkIndex++;
  }

  // clear unused chunks
  const chunks = getAllChunkedCookies(reqCookies, name);
  const chunksToRemove = chunks.length - chunkIndex;
  if (chunksToRemove > 0) {
    for (let i = 0; i < chunksToRemove; i++) {
      const chunkIndexToRemove = chunkIndex + i;
      const chunkName = `${name}${CHUNK_PREFIX}${chunkIndexToRemove}`;
      deleteCookie(resCookies, chunkName, {
        path: finalOptions.path,
        domain: finalOptions.domain,
        secure: finalOptions.secure,
        sameSite: finalOptions.sameSite,
        httpOnly: finalOptions.httpOnly
      });
      reqCookies.delete(chunkName);
    }
  }

  // When we have written chunked cookies, we should remove the non-chunked cookie
  deleteCookie(resCookies, name, {
    path: finalOptions.path,
    domain: finalOptions.domain,
    secure: finalOptions.secure,
    sameSite: finalOptions.sameSite,
    httpOnly: finalOptions.httpOnly
  });
  reqCookies.delete(name);
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

  getAllChunkedCookies(reqCookies, name, isLegacyCookie).forEach((cookie) => {
    deleteCookie(resCookies, cookie.name, options); // Delete each filtered cookie
  });
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
