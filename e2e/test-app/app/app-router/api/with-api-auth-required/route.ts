import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Demonstrates withApiAuthRequired() — returns 401 if no session, user info if authenticated.
export async function GET(req: NextRequest): Promise<Response> {
  return auth0.withApiAuthRequired(async function handler() {
    const session = await auth0.getSession();
    return NextResponse.json({ sub: session!.user.sub, email: session!.user.email });
  })(req, {}) as Promise<Response>;
}
