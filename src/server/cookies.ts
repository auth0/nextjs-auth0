import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
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
    .encrypt(encryptionSecret);

  return encryptedCookie.toString();
}

export async function decrypt<T>(cookieValue: string, secret: string) {
  const encryptionSecret = await hkdf(
    DIGEST,
    secret,
    "",
    ENCRYPTION_INFO,
    BYTE_LENGTH
  );

  const cookie = await jose.jwtDecrypt<T>(cookieValue, encryptionSecret, {});

  return cookie;
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
}

export type ReadonlyRequestCookies = Omit<
  RequestCookies,
  "set" | "clear" | "delete"
> &
  Pick<ResponseCookies, "set" | "delete">;
export { ResponseCookies };
export { RequestCookies };
