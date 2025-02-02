import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies"
import hkdf from "@panva/hkdf"
import * as jose from "jose"

const ENC = "A256GCM"
const ALG = "dir"
const DIGEST = "sha256"
const BYTE_LENGTH = 32
const ENCRYPTION_INFO = "JWE CEK"

export async function encrypt(payload: jose.JWTPayload, secret: string) {
  const encryptionSecret = await hkdf(
    DIGEST,
    secret,
    "",
    ENCRYPTION_INFO,
    BYTE_LENGTH
  )

  const encryptedCookie = await new jose.EncryptJWT(payload)
    .setProtectedHeader({ enc: ENC, alg: ALG })
    .encrypt(encryptionSecret)

  return encryptedCookie.toString()
}

export async function decrypt<T>(cookieValue: string, secret: string) {
  const encryptionSecret = await hkdf(
    DIGEST,
    secret,
    "",
    ENCRYPTION_INFO,
    BYTE_LENGTH
  )

  const cookie = await jose.jwtDecrypt<T>(cookieValue, encryptionSecret, {})

  return cookie.payload
}

export interface CookieOptions {
  httpOnly: boolean
  sameSite: "lax" | "strict" | "none"
  secure: boolean
  path: string
  maxAge?: number
}

export type ReadonlyRequestCookies = Omit<
  RequestCookies,
  "set" | "clear" | "delete"
> &
  Pick<ResponseCookies, "set" | "delete">
export { ResponseCookies }
export { RequestCookies }

export interface EncryptAndSetCookieOptions {
  reqCookies: RequestCookies;
  resCookies: ResponseCookies;
  payload: jose.JWTPayload;
  cookieName: string;
  maxAge: number;
  cookieOptions: CookieOptions;
  secret: string;
}

export const encryptAndSet = async({
  reqCookies,
  resCookies,
  payload,
  cookieName,
  maxAge,
  cookieOptions,
  secret,
}: EncryptAndSetCookieOptions) => {
  const jwe = await encrypt(payload, secret)
  const value = jwe.toString()

  resCookies.set(cookieName, value, {
    ...cookieOptions,
    maxAge,
  })
  // to enable read-after-write in the same request for middleware
  reqCookies.set(cookieName, value)

  // check if the cookie size exceeds 4096 bytes, and if so, log a warning
  const cookieJarSizeTest = new ResponseCookies(new Headers())
  cookieJarSizeTest.set(cookieName, value, {
    ...cookieOptions,
    maxAge,
  })
  if (new TextEncoder().encode(cookieJarSizeTest.toString()).length >= 4096) {
    console.warn(
      "The session cookie size exceeds 4096 bytes, which may cause issues in some browsers. " +
        "Consider removing any unnecessary custom claims from the access token or the user profile. " +
        "Alternatively, you can use a stateful session implementation to store the session data in a data store."
    )
  }
}

export type DecryptAndGetCookieOptions = {
  reqCookies: RequestCookies | ReadonlyRequestCookies;
  cookieName: string;
  secret: string;
};

export const decryptAndGet = async <T>({
  reqCookies,
  cookieName,
  secret,
}: DecryptAndGetCookieOptions): Promise<T | null> => {
  const cookieValue = reqCookies.get(cookieName)?.value;

  if (!cookieValue) {
    return null;
  }

  return decrypt<T>(cookieValue, secret);
};