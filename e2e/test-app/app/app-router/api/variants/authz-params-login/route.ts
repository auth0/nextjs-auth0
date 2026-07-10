import { NextRequest } from "next/server";
import { auth0WithAuthzParams } from "@/lib/auth0-config-variants";

// Initiates login via the Auth0Client configured with custom authorizationParameters.
// Tests verify that ui_locales and acr_values appear in the authorize redirect URL.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const loginReq = new NextRequest(
    new URL("/auth/login", url.origin),
    { headers: req.headers }
  );
  return auth0WithAuthzParams.middleware(loginReq);
}
