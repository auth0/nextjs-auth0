import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function POST() {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json(
      { success: false, error: "No active session (ceiling may have been reached)" },
      { status: 401 }
    );
  }

  try {
    await auth0.updateSession({
      ...session,
      user: { ...session.user, updatedAt: new Date().toISOString() }
    });
    return NextResponse.json({ success: true, updatedAt: new Date().toISOString() });
  } catch (err: any) {
    return NextResponse.json(
      { success: false, error: err.message },
      { status: 409 }
    );
  }
}
