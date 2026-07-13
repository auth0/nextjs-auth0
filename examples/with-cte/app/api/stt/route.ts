import { NextRequest, NextResponse } from "next/server";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "@auth0/nextjs-auth0/server";
import type { SessionTransferTokenOptions } from "@auth0/nextjs-auth0/types";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json(
      { code: "unauthenticated", message: "Not authenticated." },
      { status: 401 }
    );
  }

  let body: Partial<SessionTransferTokenOptions> & { targetLoginUrl?: string };
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
        message: "subjectToken and subjectTokenType are required."
      },
      { status: 400 }
    );
  }

  if (!body.targetLoginUrl) {
    return NextResponse.json(
      { code: "invalid_request", message: "targetLoginUrl is required." },
      { status: 400 }
    );
  }

  try {
    const result = await auth0.requestSessionTransferToken({
      subjectToken: body.subjectToken,
      subjectTokenType: body.subjectTokenType,
      reason: body.reason,
      organization: body.organization,
      scope: body.scope,
      actor: body.actor
    });

    // Force scope to "openid profile" on the target login URL. Impersonated
    // sessions cannot be granted a refresh token, so requesting `offline_access`
    // (part of the SDK's default scope) makes /authorize fail with
    // `interaction_required`. Passing scope on the login URL overrides the
    // SDK default when handleLogin forwards it to /authorize.
    const targetUrl = new URL(body.targetLoginUrl);
    if (!targetUrl.searchParams.has("scope")) {
      targetUrl.searchParams.set("scope", "openid profile");
    }

    const redirectResponse = auth0.buildSessionTransferRedirect(
      targetUrl.toString(),
      result,
      { organization: body.organization }
    );

    // Return the redirect URL to the client so it can navigate there
    return NextResponse.json({
      redirectUrl: redirectResponse.headers.get("location"),
      expiresIn: result.expiresIn
    });
  } catch (err: unknown) {
    if (err instanceof CustomTokenExchangeError) {
      const status =
        err.code === CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE ? 400 : 400;
      return NextResponse.json(
        {
          code: err.code,
          message: err.message,
          cause:
            err.cause && typeof err.cause === "object" && "code" in err.cause
              ? {
                  code: (err.cause as { code?: string }).code,
                  message: (err.cause as { message?: string }).message
                }
              : undefined
        },
        { status }
      );
    }

    console.error("STT unexpected error", err);
    return NextResponse.json(
      { code: "unexpected_error", message: "Internal server error." },
      { status: 500 }
    );
  }
}
