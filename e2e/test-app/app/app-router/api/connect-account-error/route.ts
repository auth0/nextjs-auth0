import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.connectAccount() without a session so ConnectAccountError is thrown.
// Returns e.name and e.code so specs can assert on error class identity.
// Query params:
//   ?connection=<connection-name>  (default: "google-oauth2")
export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const connection = searchParams.get("connection") ?? "google-oauth2";

  try {
    const res = await auth0.connectAccount({
      connection,
      returnTo: `${origin}/app-router/server`,
    });
    return res;
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message, code: e.code, name: e.name },
      { status: 401 }
    );
  }
}
