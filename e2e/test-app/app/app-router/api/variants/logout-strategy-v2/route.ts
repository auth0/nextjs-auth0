import { NextRequest } from "next/server";
import { auth0LogoutStrategyV2 } from "@/lib/auth0-config-variants";

// Returns the logout redirect URL so tests can inspect which endpoint is used.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  // Simulate a logout request — pass through to the v2 logout handler
  const logoutReq = new NextRequest(
    new URL("/auth/logout", url.origin),
    { headers: req.headers }
  );
  const res = await auth0LogoutStrategyV2.middleware(logoutReq);
  // Return the Location header so the test can assert on v2/logout vs end_session
  return Response.json({ location: res.headers.get("location") }, { status: 200 });
}
