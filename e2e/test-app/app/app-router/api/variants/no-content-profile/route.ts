import { NextRequest } from "next/server";
import { auth0NoContentProfile } from "@/lib/auth0-config-variants";

// Calls /auth/profile via the no-content-profile variant — returns 204 when unauthenticated.
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const profileReq = new NextRequest(
    new URL("/auth/profile", url.origin),
    { headers: req.headers }
  );
  return auth0NoContentProfile.middleware(profileReq);
}
