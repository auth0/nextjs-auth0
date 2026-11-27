import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

// Lists the user's connected accounts (My Account API).
export async function GET() {
  try {
    return NextResponse.json(await auth0.getConnectedAccounts());
  } catch (err) {
    return error(err);
  }
}

// Disconnects every account of a connection and removes its cached tokens from the session.
export async function DELETE(req: NextRequest) {
  const connection = req.nextUrl.searchParams.get("connection");
  if (!connection) {
    return NextResponse.json({ error: "connection is required" }, { status: 400 });
  }
  try {
    await auth0.disconnectAccount({ connection });
    return NextResponse.json({ disconnected: connection });
  } catch (err) {
    return error(err);
  }
}

function error(err: unknown) {
  const { code, message } = err as { code?: string; message?: string };
  return NextResponse.json({ error: code ?? "error", message }, { status: 400 });
}
