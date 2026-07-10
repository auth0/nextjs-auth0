import { NextRequest } from "next/server";
import { auth0NoIdTokenHint } from "@/lib/auth0-config-variants";

// Performs logout via the no-id-token-hint variant and returns the redirect URL.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const logoutReq = new NextRequest(
    new URL("/auth/logout", url.origin),
    { headers: req.headers }
  );
  const res = await auth0NoIdTokenHint.middleware(logoutReq);
  return Response.json({ location: res.headers.get("location") }, { status: 200 });
}
