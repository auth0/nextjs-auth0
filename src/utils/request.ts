import type { IncomingMessage } from "http";
import { NextApiRequest } from "next";
import { NextRequest } from "next/server.js";

type Req =
  | IncomingMessage
  | NextApiRequest
  | NextRequest
  | Request
  | Record<string, any>;

export const isRequest = (req: Req): boolean => {
  return (
    req instanceof Request ||
    req.headers instanceof Headers ||
    typeof (req as Request).bodyUsed === "boolean"
  );
};

export function isPrefetch(req: NextRequest): boolean {
  const h = req.headers;
  return (
    h.get("next-router-prefetch") === "1" ||
    h.has("next-router-segment-prefetch") ||
    h.get("rsc") === "1" ||
    req.nextUrl.searchParams.has("_rsc") ||
    (h.get("sec-fetch-mode") === "cors" &&
      h.get("sec-fetch-dest") === "empty" &&
      h.has("next-url"))
  );
}