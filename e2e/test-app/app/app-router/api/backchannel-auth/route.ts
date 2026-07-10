import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

// Calls auth0.getTokenByBackchannelAuth() (CIBA flow).
// Used to verify:
//   - The route dispatches to backchannelAuthentication() in auth-client
//   - Missing/invalid options produce a structured error (not 500)
//   - BackchannelAuthenticationNotSupportedError is surfaced when tenant lacks CIBA
//
// POST body: { bindingMessage, loginHint: { sub }, requestedExpiry? }
export async function POST(req: NextRequest) {
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }

  const { bindingMessage, loginHint, requestedExpiry } = body as {
    bindingMessage?: string;
    loginHint?: { sub: string };
    requestedExpiry?: number;
  };

  if (!bindingMessage || !loginHint?.sub) {
    return NextResponse.json(
      { error: "bindingMessage and loginHint.sub are required" },
      { status: 400 }
    );
  }

  try {
    const result = await auth0.getTokenByBackchannelAuth({
      bindingMessage,
      loginHint: { sub: loginHint.sub },
      ...(requestedExpiry !== undefined && { requestedExpiry }),
    });
    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message, code: e.code, name: e.name },
      { status: 400 }
    );
  }
}
