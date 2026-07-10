import { NextRequest } from "next/server";
import { auth0WithPAR } from "@/lib/auth0-config-variants";

// Initiates login via the PAR-enabled Auth0Client.
// The authorize redirect URL will carry ?request_uri= instead of inline params
// when PAR succeeds, or fall back to inline params when the tenant lacks PAR support.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const loginReq = new NextRequest(
    new URL("/auth/login", url.origin),
    { headers: req.headers }
  );
  return auth0WithPAR.middleware(loginReq);
}
