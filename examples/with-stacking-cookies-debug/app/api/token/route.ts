import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function GET() {
  try {
    const tokenSet = await auth0.getAccessToken();
    return NextResponse.json({
      accessToken: tokenSet.token,
      expiresAt: tokenSet.expiresAt,
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 401 });
  }
}
