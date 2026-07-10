import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls getAccessToken({ refresh: true }) — forces a token refresh regardless of expiry.
export async function GET() {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const { token, expiresAt } = await auth0.getAccessToken({ refresh: true });
    return NextResponse.json({ token, expiresAt });
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 401 });
  }
}
