import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.passwordless.start() — tests the server passwordless start method.
export async function POST(req: NextRequest) {
  const body = await req.json();
  try {
    await auth0.passwordless.start(body);
    return NextResponse.json({ ok: true });
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
