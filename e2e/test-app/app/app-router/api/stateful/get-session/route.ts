import { NextResponse } from "next/server";
import { auth0Stateful } from "@/lib/auth0-stateful";

export async function GET() {
  const session = await auth0Stateful.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json(session);
}
