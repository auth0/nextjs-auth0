import { NextRequest, NextResponse } from "next/server";

import type { CustomTokenExchangeOptions } from "@auth0/nextjs-auth0/types";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json({ message: "Not authenticated" }, { status: 401 });
  }

  let body: Partial<CustomTokenExchangeOptions>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { code: "invalid_request", message: "Request body must be JSON." },
      { status: 400 }
    );
  }

  if (!body.subjectToken || !body.subjectTokenType) {
    return NextResponse.json(
      {
        code: "invalid_request",
        message: "subjectToken and subjectTokenType are required.",
      },
      { status: 400 }
    );
  }

  try {
    const result = await auth0.customTokenExchange({
      subjectToken: body.subjectToken,
      subjectTokenType: body.subjectTokenType,
      audience: body.audience,
      scope: body.scope,
      actorToken: body.actorToken,
      actorTokenType: body.actorTokenType,
    });

    return NextResponse.json({
      accessToken: result.accessToken,
      act: result.act,
    });
  } catch (err: unknown) {
    const sdkErr =
      err && typeof err === "object" && "code" in err
        ? (err as {
            code: string;
            message?: string;
            cause?: { code?: string; message?: string };
          })
        : null;

    if (sdkErr?.code) {
      return NextResponse.json(
        {
          code: sdkErr.code,
          message: sdkErr.message ?? "Token exchange failed.",
          cause: sdkErr.cause
            ? { code: sdkErr.cause.code, message: sdkErr.cause.message }
            : undefined,
        },
        { status: 400 }
      );
    }

    console.error("CTE unexpected error", err);
    return NextResponse.json(
      { code: "unexpected_error", message: "Internal server error." },
      { status: 500 }
    );
  }
}
