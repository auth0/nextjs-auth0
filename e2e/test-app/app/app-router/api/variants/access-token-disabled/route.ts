import { NextRequest, NextResponse } from "next/server";
import { auth0AccessTokenEndpointDisabled } from "@/lib/auth0-config-variants";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const authReq = new NextRequest(new URL("/auth/access-token", url.origin), { headers: req.headers });
  const res = await auth0AccessTokenEndpointDisabled.middleware(authReq);
  // middleware() returns NextResponse.next() for routes it doesn't own (i.e. disabled endpoints).
  // In a route handler, next() is not meaningful — return 404 to indicate the endpoint is disabled.
  if (res.headers.get("x-middleware-next") === "1" || res.status === 200 && !res.body) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return res;
}
