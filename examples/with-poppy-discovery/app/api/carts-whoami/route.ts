import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

// TEMP DEBUG, remove after testing: asks the carts API what it verified about this browser's token.
// Uses the guest's token for an agent guest, and the customer's token for a signed-in session.
// The token is sent to the carts API and never returned.
const API = process.env.CARTS_API_URL ?? "http://localhost:4000";

export async function GET() {
  const session = await auth0.getSession();
  const guest = session ? null : await auth0.getAnonymousSession();
  const token = session?.tokenSet.accessToken ?? guest?.accessToken;
  if (!token) {
    return NextResponse.json({ error: "no session" }, { status: 401 });
  }

  const response = await fetch(`${API}/whoami`, {
    headers: { authorization: `Bearer ${token}` },
    cache: "no-store"
  });
  return NextResponse.json(
    { using: session ? "customer session token" : "guest token", status: response.status, answer: await response.json() },
    { headers: { "Cache-Control": "no-store" } }
  );
}
