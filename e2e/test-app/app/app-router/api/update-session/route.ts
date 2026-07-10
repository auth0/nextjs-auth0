import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function POST() {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  await auth0.updateSession({ ...session, user: { ...session.user, updatedAt: Date.now() } });
  return NextResponse.json({ ok: true });
}
