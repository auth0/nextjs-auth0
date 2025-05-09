import {
  RequestCookie,
  RequestCookies,
  ResponseCookies
} from "@edge-runtime/cookies";
import hkdf from "@panva/hkdf";
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

export async function decrypt<T>(cookieValue: string, secret: string) {
  try {
    const encryptionSecret = await hkdf(
      DIGEST,
      secret,
      "",
      ENCRYPTION_INFO,
      BYTE_LENGTH
    );

    const cookie = await jose.jwtDecrypt<T>(cookieValue, encryptionSecret, {});

    return cookie;
  } catch (e: any) {
    if (e.code === "ERR_JWT_EXPIRED") {
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

/**
 * Retrieves the index of a cookie based on its name.
 *
 * @param name - The name of the cookie.
 * @returns The index of the cookie. Returns undefined if no index is found.
 */
const getChunkedCookieIndex = (name: string): number | undefined => {
  const match = CHUNK_INDEX_REGEX.exec(name);
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
  name: string
): RequestCookie[] => {
  const chunkedCookieRegex = new RegExp(`^${name}${CHUNK_PREFIX}\\d+$`);
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
    getAllChunkedCookies(reqCookies, name).forEach((cookieChunk) => {
      resCookies.delete(cookieChunk.name);
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
      resCookies.delete(chunkName);
      reqCookies.delete(chunkName);
    }
  }

  // When we have written chunked cookies, we should remove the non-chunked cookie
  resCookies.delete(name);
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
  reqCookies: RequestCookies
): string | undefined {
  // Check if regular cookie exists
  const cookie = reqCookies.get(name);
  if (cookie?.value) {
    return cookie.value;
  }

  const chunks = getAllChunkedCookies(reqCookies, name).sort(
    // Extract index from cookie name and sort numerically
    (first, second) => {
      return (
        getChunkedCookieIndex(first.name)! - getChunkedCookieIndex(second.name)!
      );
    }
  );

  if (chunks.length === 0) {
    return undefined;
  }

  // Validate sequence integrity - check for missing chunks
  const highestIndex = getChunkedCookieIndex(chunks[chunks.length - 1].name)!;
  if (chunks.length !== highestIndex + 1) {
    console.warn(
      `Incomplete chunked cookie '${name}': Found ${chunks.length} chunks, expected ${highestIndex + 1}`
    );

    // TODO: Invalid sequence, delete all chunks
    // this cannot be done here rn because we don't have access to the response cookies
    // deleteChunkedCookie(name, reqCookies, resCookies);

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
 */
export function deleteChunkedCookie(
  name: string,
  reqCookies: RequestCookies,
  resCookies: ResponseCookies
): void {
  // Delete main cookie
  resCookies.delete(name);

  getAllChunkedCookies(reqCookies, name).forEach((cookie) => {
    resCookies.delete(cookie.name); // Delete each filtered cookie
  });
}
