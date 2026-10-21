import { cookies, headers } from "next/headers.js";
import { NextResponse, type NextRequest } from "next/server.js";
import { RequestCookies, type ResponseCookies } from "@edge-runtime/cookies";

import {
  toHeadersFromIncomingMessage,
  toNextRequest,
  toUrlFromPagesRouter
} from "../http/next-compat.js";
import type { ReadonlyRequestCookies } from "../types/cookies.js";
import type { PagesRouterRequest } from "../types/index.js";

/**
 * Per-request cookie access handed to the engine as its store options.
 *
 * In a Server Action both fields are the same `cookies()` store from `next/headers`.
 */
export interface CookieContext {
  reqCookies: RequestCookies | ReadonlyRequestCookies;
  /**
   * Where writes and deletes go. When absent, writes and deletes are skipped (read-only call).
   */
  resCookies?: ResponseCookies | ReadonlyRequestCookies;
  /**
   * When `true`, a write that throws (a Server Component cannot set cookies) is ignored and
   * `writeFailed` is set instead, so the caller can still return its result.
   */
  ignoreWriteErrors?: boolean;
  /**
   * Set by the cookie handler when a write was ignored because of `ignoreWriteErrors`.
   */
  writeFailed?: boolean;
  /**
   * Request headers, passed to the user's domain resolver.
   */
  headers?: Headers;
  /**
   * Request URL, passed to the user's domain resolver. Absent in Server Components and Server Actions.
   */
  url?: URL;
}

/**
 * The context for a middleware call: reads from the request, writes to the response returned.
 */
export function middlewareContext(
  req: NextRequest,
  res: NextResponse
): CookieContext {
  return {
    reqCookies: req.cookies,
    resCookies: res.cookies,
    headers: req.headers,
    url: req.nextUrl
  };
}

export interface ReadContext {
  /**
   * Read-only: no `resCookies`, so any write the engine attempts is skipped.
   */
  ctx: CookieContext;
  /**
   * The request as a `NextRequest`, when one was given (not for the Pages Router or `cookies()`).
   */
  nextReq?: NextRequest;
}

/**
 * The context for a call that only reads: a Route Handler or middleware request, a Pages Router
 * request, or no request at all (Server Components and Actions, where cookies and headers come
 * from `next/headers`).
 */
export async function readContext(
  input?: Request | PagesRouterRequest | NextRequest
): Promise<ReadContext> {
  if (input instanceof Request) {
    const nextReq = toNextRequest(input);
    return {
      ctx: {
        reqCookies: nextReq.cookies,
        headers: nextReq.headers,
        url: nextReq.nextUrl
      },
      nextReq
    };
  }

  if (input) {
    const headers = toHeadersFromIncomingMessage(input);
    return {
      ctx: {
        reqCookies: new RequestCookies(headers),
        headers,
        url: toUrlFromPagesRouter(input)
      }
    };
  }

  return {
    ctx: { reqCookies: await cookies(), headers: await headers() }
  };
}

export interface RequestContext extends ReadContext {
  /**
   * Holds the cookies the engine wrote; copy them onto the response with `transferCookies`.
   * The response a route returns is not known until the engine is done, so writes go here.
   */
  scratch: NextResponse;
}

/**
 * Like {@link readContext}, and writes go to a scratch response.
 */
export async function requestContext(
  input?: Request | PagesRouterRequest | NextRequest
): Promise<RequestContext> {
  const scratch = NextResponse.next();
  const { ctx, nextReq } = await readContext(input);
  return { ctx: { ...ctx, resCookies: scratch.cookies }, scratch, nextReq };
}

/**
 * The context for a call with no response object (Server Actions, Route Handlers): reads and
 * writes go to the same `cookies()` store. A write Next refuses (a Server Component) throws,
 * unless `ignoreWriteErrors` is set.
 */
export async function sharedJarContext({
  ignoreWriteErrors
}: { ignoreWriteErrors?: boolean } = {}): Promise<CookieContext> {
  const jar = await cookies();
  return {
    reqCookies: jar,
    resCookies: jar,
    headers: await headers(),
    ...(ignoreWriteErrors && { ignoreWriteErrors })
  };
}
