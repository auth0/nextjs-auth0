import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.passwordless.challengeWithPhoneNumber() — server SMS OTP challenge.
export async function POST(req: NextRequest) {
  const body = await req.json();
  try {
    const result = await auth0.passwordless.challengeWithPhoneNumber(body);
    return NextResponse.json(result ?? { ok: true });
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
