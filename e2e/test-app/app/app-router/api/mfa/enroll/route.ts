import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.mfa.enroll() directly — tests the server MFA enroll method.
export async function POST(req: NextRequest) {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const body = await req.json();
  if (!body.mfaToken) return NextResponse.json({ error: "mfaToken required" }, { status: 400 });
  try {
    const result = await auth0.mfa.enroll(body);
    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
