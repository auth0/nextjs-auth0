import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function GET() {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const { token, expiresAt, scope, token_type } = await auth0.getAccessToken();
    return NextResponse.json({ token, expiresAt, scope, token_type });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
