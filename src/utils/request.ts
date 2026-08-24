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
 * `sec-purpose` matching:
 * - `prefetch` alone → prefetch, block it.
 * - `prefetch;prerender` → Speculation Rules prerender. The browser activates
 *   this as the real navigation when the user clicks, so blocking it with 204
 *   would silently swallow the login click. Excluded by requiring the value
 *   does not contain `prerender`.
 *
 * Intentionally excludes:
 * - `sec-fetch-mode` — also set on legitimate fetch()/XHR calls to /auth/login.
 * - `accept: text/x-component` — sent by ALL App Router RSC requests, including
 *   real client-side `<Link>` navigations (e.g. `<Link prefetch={false}>`), so
 *   matching it would 401 genuine login clicks, not just prefetches.
 *
 * Note: `x-middleware-prefetch` is a Pages Router signal only
 * (`shared/lib/router/router.js`). It never fires on App Router prefetch paths,
 * but is kept for Pages Router coverage.
 */
export const isNonNavigationalRequest = (req: NextRequest): boolean => {
  const secPurpose = req.headers.get("sec-purpose") ?? "";
  const routerPrefetch = req.headers.get("next-router-prefetch");
  return (
    // next-router-prefetch: "1" = AUTO prefetch (Next 15); "2" = runtime
    // prefetch (Next 16+). Accept any truthy non-"0"/non-"false" value to
    // cover future Next versions, but reject falsy values a proxy or client
    // might set explicitly — matching those would silently 204 real logins.
    isTruthyHeaderValue(routerPrefetch) ||
    req.headers.get("purpose") === "prefetch" ||
    (secPurpose.includes("prefetch") && !secPurpose.includes("prerender")) ||
    req.headers.get("x-middleware-prefetch") === "1"
  );
};

const isTruthyHeaderValue = (value: string | null): boolean => {
  if (!value) return false;
  const normalized = value.trim().toLowerCase();
  return normalized !== "" && normalized !== "0" && normalized !== "false";
};
