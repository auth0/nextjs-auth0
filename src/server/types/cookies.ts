import type { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

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
