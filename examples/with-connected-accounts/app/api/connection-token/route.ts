import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

// Gets an access token for the provider (Token Vault). The token itself stays on the server: call
// the provider's API from here, and send the browser only what it needs.
export async function POST(req: NextRequest) {
  const { connection, loginHint } = await req.json();

  try {
    const { token, expiresAt } = await auth0.getAccessTokenForConnection({
      connection,
      ...(loginHint && { login_hint: loginHint }),
    });
    return NextResponse.json({
      tokenLength: token.length,
      expiresInSeconds: expiresAt - Math.floor(Date.now() / 1000),
    });
  } catch (err) {
    const { code, message } = err as { code?: string; message?: string };
    return NextResponse.json({ error: code ?? "error", message }, { status: 400 });
  }
}
