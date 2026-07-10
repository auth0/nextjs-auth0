import { NextResponse } from "next/server";
import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Auth0Client with tokenRefreshBuffer=3600 — tokens expiring within 1 hour are proactively refreshed.
const auth0WithBuffer = new Auth0Client({ tokenRefreshBuffer: 3600 });

export async function GET() {
  const session = await auth0WithBuffer.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const { token, expiresAt } = await auth0WithBuffer.getAccessToken();
    return NextResponse.json({ token, expiresAt });
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 401 });
  }
}
