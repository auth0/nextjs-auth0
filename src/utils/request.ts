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
 * Returns true only when a request carries a known prefetch signal.
 * Used to block Next.js prefetch requests from triggering handleLogin.
 *
 * Intentionally excludes `sec-fetch-mode` — that header also matches
 * legitimate fetch()/XHR calls to /auth/login which must not be blocked.
 */
export const isNonNavigationalRequest = (req: NextRequest): boolean => {
  return (
    req.headers.get("next-router-prefetch") === "1" ||
    req.headers.get("accept") === "text/x-component" ||
    req.headers.get("purpose") === "prefetch" ||
    req.headers.get("sec-purpose") === "prefetch" ||
    req.headers.get("x-middleware-prefetch") === "1"
  );
};
