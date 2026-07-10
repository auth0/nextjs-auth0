import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.passkey.register() — issues the WebAuthn registration challenge.
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  try {
    const result = await auth0.passkey.register(body);
    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
