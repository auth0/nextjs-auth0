import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.createFetcher() and makes a request to the given URL.
// Used to verify:
//   - createFetcher() throws MISSING_SESSION when no session exists
//   - createFetcher() returns a Fetcher instance when authenticated
//   - fetchWithAuth() sends Authorization: Bearer header on requests
//
// Query params:
//   ?url=<absolute URL>     — target URL for fetchWithAuth (defaults to /auth/profile)
export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const target = searchParams.get("url") ?? `${origin}/auth/profile`;

  try {
    const fetcher = await auth0.createFetcher(req, { baseUrl: origin });
    const res = await fetcher.fetchWithAuth(target);
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    return NextResponse.json({
      status: res.status,
      ok: res.ok,
      body,
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message, code: e.code },
      { status: e.code === "missing_session" ? 401 : 400 }
    );
  }
}
