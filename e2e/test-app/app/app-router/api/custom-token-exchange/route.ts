import { NextRequest, NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  try {
    const result = await auth0.customTokenExchange({
      subjectToken: body.subjectToken,
      subjectTokenType: body.subjectTokenType ?? "urn:ietf:params:oauth:token-type:access_token",
      audience: body.audience,
    });
    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message, code: e.code }, { status: 400 });
  }
}
