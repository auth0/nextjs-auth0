import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

export * from "./encryption.js";
export * from "./chunks.js";

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
