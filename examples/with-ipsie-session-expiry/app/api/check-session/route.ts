import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function GET() {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json({ session: null, expired: true });
  }

  const ceiling = session.internal?.sessionExpiresAt ?? null;
  const now = Math.floor(Date.now() / 1000);

  return NextResponse.json({
    session: {
      user: session.user,
      sessionExpiresAt: ceiling,
      remainingSeconds: ceiling ? ceiling - now : null
    },
    expired: false
  });
}
