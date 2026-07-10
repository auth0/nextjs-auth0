import { NextResponse } from "next/server";
import { auth0BeforeSessionSaved } from "@/lib/auth0-config-variants";

export async function GET() {
  const session = await auth0BeforeSessionSaved.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json({ injectedClaim: session.user.injectedClaim });
}
