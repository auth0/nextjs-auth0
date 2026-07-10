import { NextResponse } from "next/server";
import { auth0Stateful } from "@/lib/auth0-stateful";

export async function POST() {
  const session = await auth0Stateful.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  await auth0Stateful.updateSession({
    ...session,
    user: { ...session.user, updatedAt: Date.now() },
  });
  return NextResponse.json({ ok: true });
}
