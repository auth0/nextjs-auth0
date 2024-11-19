import { NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function GET() {
  const session = await auth0.getSession()

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  return NextResponse.json({ email: session.user.email }, { status: 200 })
}
