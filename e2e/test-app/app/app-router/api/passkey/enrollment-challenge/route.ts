import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.passkey.enrollmentChallenge() — issues a passkey enrollment challenge for an authenticated user.
export async function POST(req: NextRequest) {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  try {
    const result = await auth0.passkey.enrollmentChallenge(body);
    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
