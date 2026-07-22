import { NextRequest, NextResponse } from "next/server";
import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "@auth0/nextjs-auth0/server";

import { auth0 } from "@/lib/auth0";

// Only the fields the form actually sends. `actor` is intentionally not accepted here —
// it must come from the agent's own session (the SDK default), never from the request body.
type SttRequestBody = {
  subjectToken?: string;
  subjectTokenType?: string;
  targetLoginUrl?: string;
  reason?: string;
  organization?: string;
};

// SECURITY: targetLoginUrl must be a trusted, app-controlled value — never pass
// untrusted user input here. In production, validate the origin against an
// allowlist (e.g. STT_ALLOWED_ORIGINS env var) before calling requestSessionTransferToken.
// The STT is a single-use credential; attaching it to a wrong host leaks the token.
//
// Defaults to this app's own origin (APP_BASE_URL) rather than "allow everything" —
// this example mints and redeems the STT in the same app, so that's the only origin
// it legitimately needs. Set STT_ALLOWED_ORIGINS explicitly for a multi-app deployment.
const ALLOWED_ORIGINS = new Set(
  (process.env.STT_ALLOWED_ORIGINS
    ? process.env.STT_ALLOWED_ORIGINS.split(",")
    : [process.env.APP_BASE_URL ?? ""]
  )
    .map((s) => s.trim())
    .filter(Boolean)
);

export async function POST(req: NextRequest) {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json(
      { code: "unauthenticated", message: "Not authenticated." },
      { status: 401 }
    );
  }

  let body: SttRequestBody;
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
  // so we must not spend one on a request we can't complete.
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
  if (!ALLOWED_ORIGINS.has(targetUrl.origin)) {
    return NextResponse.json(
      {
        code: "invalid_request",
        message: `targetLoginUrl origin "${targetUrl.origin}" is not in the allowed list.`
      },
      { status: 400 }
    );
  }

  // Force the /authorize `scope` param (a different scope from the STT exchange below):
  // impersonated sessions cannot get a refresh token, so the SDK's default `offline_access`
  // exchange scope would make /authorize fail with `interaction_required`. Setting the
  // login-URL scope here overrides that default when handleLogin forwards it to /authorize.
  if (!targetUrl.searchParams.has("scope")) {
    targetUrl.searchParams.set("scope", "openid profile");
  }

  try {
    // actor is intentionally NOT sourced from the request body: it must come from the
    // agent's own session, not from whatever the caller posts. Omitting it here lets the
    // SDK default to the agent session's ID token, which is the pattern this example
    // demonstrates. This form also never sends a custom exchange scope.
    const result = await auth0.requestSessionTransferToken({
      subjectToken: body.subjectToken,
      subjectTokenType: body.subjectTokenType,
      reason: body.reason,
      organization: body.organization
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
      // ACTOR_UNAVAILABLE and bad-input cases are client errors (400).
      // SESSION_TRANSFER_DISABLED and SETACTOR_REQUIRED mean the tenant or Action
      // is misconfigured — those are server/operator errors (500).
      const serverErrorCodes = new Set([
        CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED,
        CustomTokenExchangeErrorCode.SETACTOR_REQUIRED
      ]);
      const status = serverErrorCodes.has(
        err.code as CustomTokenExchangeErrorCode
      )
        ? 500
        : 400;
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
