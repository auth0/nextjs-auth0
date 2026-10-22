import { cookies } from "next/headers.js";
import { NextResponse, type NextRequest } from "next/server.js";
import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

import { isRequest } from "../../utils/request.js";
import {
  toHeadersFromIncomingMessage,
  toNextRequest,
  toUrlFromPagesRouter
} from "../http/next-compat.js";
import { appendPagesRouterCookies } from "../http/pages-router.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import {
  middlewareContext,
  readContext,
  sharedJarContext,
  type CookieContext
} from "./context.js";

/**
 * Runs `run` with the cookies of nextjs's call forms (`saveToSession`):
 * - no `res`: the App Router form; writes go to `cookies()`, and a write Next refuses (a Server
 *   Component) is skipped with nextjs's dev warning, so the result is still returned. With a
 *   `req` (`requestSessionTransferToken(req, undefined, options)`), the session is read from it.
 *   With `ignoreWriteErrors: false` that write throws instead (`mfa.verify`, as on nextjs).
 * - `NextRequest` / `Request` and a `NextResponse`: middleware; writes go to the response.
 * - otherwise the Pages Router: writes are appended to `res` as `Set-Cookie`.
 */
export async function withCallContext<T>(
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined,
  run: (ctx: CookieContext) => Promise<T>,
  { ignoreWriteErrors = true }: { ignoreWriteErrors?: boolean } = {}
): Promise<T> {
  if (!req || !res) {
    let ctx: CookieContext;
    // Writes to here only when `cookies()` is not available (the Pages Router); they are lost,
    // as on nextjs.
    const dropped = new Headers();
    if (req) {
      const { ctx: read } = await readContext(req);
      let jar: Awaited<ReturnType<typeof cookies>> | undefined;
      try {
        jar = await cookies();
      } catch {
        jar = undefined;
      }
      ctx = {
        ...read,
        resCookies: jar ?? new ResponseCookies(dropped),
        ...(ignoreWriteErrors && { ignoreWriteErrors })
      };
    } else {
      ctx = await sharedJarContext({ ignoreWriteErrors });
    }
    try {
      return await run(ctx);
    } finally {
      if (
        (ctx.writeFailed || dropped.has("set-cookie")) &&
        process.env.NODE_ENV === "development"
      ) {
        console.warn(
          "Failed to persist the updated token set. `getAccessToken()` was likely called from a Server Component which cannot set cookies."
        );
      }
    }
  }

  if (isRequest(req) && res instanceof NextResponse) {
    // Middleware.
    return run(middlewareContext(toNextRequest(req), res));
  }

  // Pages Router: the cookies are written to a holder, then appended to the response.
  const written = new Headers();
  const headers = toHeadersFromIncomingMessage(req as PagesRouterRequest);
  const ctx: CookieContext = {
    reqCookies: new RequestCookies(headers),
    resCookies: new ResponseCookies(written),
    headers,
    url: toUrlFromPagesRouter(req as PagesRouterRequest)
  };
  try {
    return await run(ctx);
  } finally {
    appendPagesRouterCookies(res as PagesRouterResponse, written);
  }
}
