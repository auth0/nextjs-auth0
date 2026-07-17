import type { IncomingMessage } from "http";
import { NextApiRequest } from "next";
import type { NextRequest } from "next/server.js";

type Req =
  | IncomingMessage
  | NextApiRequest
  | NextRequest
  | Request
  | Record<string, any>;

export const isRequest = (req: Req): req is Request | NextRequest => {
  return (
    req instanceof Request ||
    req.headers instanceof Headers ||
    typeof (req as Request).bodyUsed === "boolean"
  );
};

/**
 * Returns true only when a request carries an unambiguous prefetch signal.
 * Used to block Next.js prefetch requests from triggering handleLogin.
 *
 * Only headers that are exclusive to prefetches are checked:
 * - `next-router-prefetch` / `x-middleware-prefetch` — Next.js prefetch markers
 * - `purpose` / `sec-purpose` = `prefetch` — W3C/browser prefetch hints
 *
 * Intentionally excludes:
 * - `sec-fetch-mode` — also set on legitimate fetch()/XHR calls to /auth/login.
 * - `accept: text/x-component` — sent by ALL App Router RSC requests, including
 *   real client-side `<Link>` navigations (e.g. `<Link prefetch={false}>`), so
 *   matching it would 401 genuine login clicks, not just prefetches.
 */
export const isNonNavigationalRequest = (req: NextRequest): boolean => {
  return (
    req.headers.get("next-router-prefetch") === "1" ||
    req.headers.get("purpose") === "prefetch" ||
    req.headers.get("sec-purpose") === "prefetch" ||
    req.headers.get("x-middleware-prefetch") === "1"
  );
};
