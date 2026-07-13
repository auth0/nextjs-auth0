import { NextRequest, NextResponse } from "next/server";

import { CustomTokenExchangeError } from "@auth0/nextjs-auth0/server";
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

  // Validate the target URL BEFORE minting — the STT is one-shot and short-lived,
  // so we must not spend one on a request we can't complete. Also force scope to
  // "openid profile": impersonated sessions cannot get a refresh token, so the
  // SDK's default `offline_access` scope would make /authorize fail with
  // `interaction_required`. Passing scope on the login URL overrides the SDK
  // default when handleLogin forwards it to /authorize.
  let targetUrl: URL;
  try {
    targetUrl = new URL(body.targetLoginUrl);
  } catch {
    return NextResponse.json(
      {
        code: "invalid_request",
        message: "targetLoginUrl must be an absolute URL."
      },
      { status: 400 }
    );
  }
  if (!targetUrl.searchParams.has("scope")) {
    targetUrl.searchParams.set("scope", "openid profile");
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

    const redirectResponse = auth0.buildSessionTransferRedirect(
      targetUrl.toString(),
      result,
      { organization: body.organization }
    );

    const redirectUrl = redirectResponse.headers.get("location");
    if (!redirectUrl) {
      return NextResponse.json(
        {
          code: "unexpected_error",
          message: "Failed to build the session transfer redirect URL."
        },
        { status: 500 }
      );
    }

    // Return the redirect URL to the client so it can navigate there
    return NextResponse.json({ redirectUrl, expiresIn: result.expiresIn });
  } catch (err: unknown) {
    if (err instanceof CustomTokenExchangeError) {
      // All STT exchange failures (bad input, missing actor, disabled feature,
      // upstream exchange error) are surfaced to the client as 400 with the typed
      // code and the underlying cause for diagnosis.
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
        { status: 400 }
      );
    }

    console.error("STT unexpected error", err);
    return NextResponse.json(
      { code: "unexpected_error", message: "Internal server error." },
      { status: 500 }
    );
  }
}
