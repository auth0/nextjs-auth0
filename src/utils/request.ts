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
 * Returns true if the request is non-navigational (e.g. a prefetch, fetch, or
 * XHR) rather than a full browser navigation. Used to guard against Next.js
 * prefetch requests triggering side-effectful handlers like handleLogin.
 *
 * Uses the W3C Fetch Metadata `sec-fetch-mode` header as the primary signal
 * (supported in Chrome 76+, Firefox 90+, Safari 16.4+). Falls back to
 * Next.js-specific and legacy prefetch headers for older environments.
 */
export const isNonNavigationalRequest = (req: NextRequest): boolean => {
  const fetchMode = req.headers.get("sec-fetch-mode");
  if (fetchMode !== null) {
    return fetchMode !== "navigate";
  }

  return (
    req.headers.get("next-router-prefetch") === "1" ||
    req.headers.get("accept") === "text/x-component" ||
    req.headers.get("purpose") === "prefetch" ||
    req.headers.get("sec-purpose") === "prefetch" ||
    req.headers.get("x-middleware-prefetch") === "1"
  );
};
