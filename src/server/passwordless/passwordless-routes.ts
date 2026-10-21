import { NextRequest, NextResponse } from "next/server.js";

import {
  MfaRequiredError,
  PasswordlessDbChallengeError,
  PasswordlessDbGetTokenError,
  PasswordlessStartError,
  PasswordlessVerifyError,
  SdkError
} from "../../errors/index.js";
import type {
  PasswordlessDbChallengeEmailOptions,
  PasswordlessDbChallengePhoneOptions,
  PasswordlessStartOptions,
  PasswordlessVerifyOptions
} from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import {
  parseJsonBody,
  validateStringFieldAndThrow
} from "../../utils/mfa-validation-utils.js";
import { middlewareContext, readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import {
  challengeDbConnection,
  loginWithDbOtp,
  startPasswordless,
  verifyPasswordless
} from "./passwordless-operations.js";

/**
 * Route: POST /auth/passwordless/start, body `{ connection: "email", email, send, language? }` or
 * `{ connection: "sms", phoneNumber, language? }`. 204; a magic link's transaction cookie is set.
 */
export async function handlePasswordlessStart(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const connection = validateStringFieldAndThrow(
      body.connection,
      "connection"
    );
    const language =
      typeof body.language === "string" && body.language
        ? body.language
        : undefined;

    let options: PasswordlessStartOptions;
    if (connection === "email") {
      const email = validateStringFieldAndThrow(body.email, "email");
      const send = validateStringFieldAndThrow(body.send, "send") as
        "code" | "link";
      options = { connection: "email", email, send, language };
    } else if (connection === "sms") {
      const phoneNumber = validateStringFieldAndThrow(
        body.phoneNumber,
        "phoneNumber"
      );
      options = { connection: "sms", phoneNumber, language };
    } else {
      return invalidConnection();
    }

    const scratch = NextResponse.next();
    await startPasswordless(
      setup,
      middlewareContext(req, scratch),
      req,
      options
    );

    const res = new NextResponse(null, { status: 204 });
    transferCookies(scratch, res);
    return res;
  } catch (e) {
    if (e instanceof PasswordlessStartError) {
      if (e.error === "unexpected_error") {
        return serverError();
      }
      return NextResponse.json(e.toJSON(), { status: 400 });
    }
    return otherErrorResponse(e);
  }
}

/**
 * Route: POST /auth/passwordless/verify, body `{ connection: "email", email, verificationCode }`
 * or `{ connection: "sms", phoneNumber, verificationCode }`. The engine saves the session; 200
 * with `{ success: true }`, the session cookie and no-cache headers. MFA required: 403 with the
 * sealed token. Other `PasswordlessVerifyError`s: 403, except `discovery_error` and
 * `unexpected_error` (500).
 */
export async function handlePasswordlessVerify(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const connection = validateStringFieldAndThrow(
      body.connection,
      "connection"
    );
    const verificationCode = validateStringFieldAndThrow(
      body.verificationCode,
      "verificationCode"
    );

    let options: PasswordlessVerifyOptions;
    if (connection === "email") {
      const email = validateStringFieldAndThrow(body.email, "email");
      options = { connection: "email", email, verificationCode };
    } else if (connection === "sms") {
      const phoneNumber = validateStringFieldAndThrow(
        body.phoneNumber,
        "phoneNumber"
      );
      options = { connection: "sms", phoneNumber, verificationCode };
    } else {
      return invalidConnection();
    }

    const scratch = NextResponse.next();
    await verifyPasswordless(setup, middlewareContext(req, scratch), options);

    return loggedIn(scratch);
  } catch (e) {
    return loginErrorResponse(e, PasswordlessVerifyError, 403);
  }
}

/**
 * Route: POST /auth/passwordless/otp/challenge, body `{ email, connection, allowSignup? }` or
 * `{ phoneNumber, connection, deliveryMethod?, allowSignup? }`. 200 with `{ authSession }`.
 */
export async function handlePasswordlessDbOtpChallenge(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const connection = validateStringFieldAndThrow(
      body.connection,
      "connection"
    );
    const allowSignup =
      typeof body.allowSignup === "boolean" ? body.allowSignup : false;

    let options:
      PasswordlessDbChallengeEmailOptions | PasswordlessDbChallengePhoneOptions;
    if (typeof body.email === "string" && body.email) {
      options = { email: body.email, connection, allowSignup };
    } else if (typeof body.phoneNumber === "string" && body.phoneNumber) {
      const deliveryMethod =
        body.deliveryMethod === "voice" || body.deliveryMethod === "text"
          ? body.deliveryMethod
          : undefined;
      options = {
        phoneNumber: body.phoneNumber,
        connection,
        allowSignup,
        ...(deliveryMethod && { deliveryMethod })
      };
    } else {
      return NextResponse.json(
        {
          error: "missing_identifier",
          error_description: "Either email or phoneNumber is required"
        },
        { status: 400 }
      );
    }

    const { ctx } = await readContext(req);
    const challenge = await challengeDbConnection(setup, ctx, options);
    return NextResponse.json({ authSession: challenge.authSession });
  } catch (e) {
    if (e instanceof PasswordlessDbChallengeError) {
      if (e.error === "unexpected_error") {
        return serverError();
      }
      return NextResponse.json(e.toJSON(), { status: 400 });
    }
    return otherErrorResponse(e);
  }
}

/**
 * Route: POST /auth/passwordless/otp/token, body `{ authSession, otp }`. The engine saves the
 * session; 200 with `{ success: true }`, the session cookie and no-cache headers. MFA required:
 * 403 with the sealed token. Other `PasswordlessDbGetTokenError`s: 400, except `discovery_error`
 * and `unexpected_error` (500).
 */
export async function handlePasswordlessDbGetToken(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const authSession = validateStringFieldAndThrow(
      body.authSession,
      "authSession"
    );
    const otp = validateStringFieldAndThrow(body.otp, "otp");

    const scratch = NextResponse.next();
    await loginWithDbOtp(setup, middlewareContext(req, scratch), {
      authSession,
      otp
    });

    return loggedIn(scratch);
  } catch (e) {
    return loginErrorResponse(e, PasswordlessDbGetTokenError, 400);
  }
}

function loggedIn(scratch: NextResponse): NextResponse {
  const res = NextResponse.json({ success: true });
  transferCookies(scratch, res);
  addCacheControlHeadersForSession(res);
  return res;
}

// Verify and DB get-token: MFA required 403 with the sealed token; `discovery_error` and
// `unexpected_error` 500; other errors of the class `status`.
function loginErrorResponse(
  e: unknown,
  ErrorClass:
    typeof PasswordlessVerifyError | typeof PasswordlessDbGetTokenError,
  status: number
): NextResponse {
  if (e instanceof MfaRequiredError) {
    // `#createMfaRequiredResponse` with no session: nothing to save.
    const res = NextResponse.json(e.toJSON(), { status: 403 });
    addCacheControlHeadersForSession(res);
    return res;
  }
  if (e instanceof ErrorClass) {
    if (e.error === "discovery_error" || e.error === "unexpected_error") {
      return serverError();
    }
    return NextResponse.json(e.toJSON(), { status });
  }
  return otherErrorResponse(e);
}

// Any other SDK error 400 with its code; anything else (an app hook error included) 500.
function otherErrorResponse(e: unknown): NextResponse {
  if (e instanceof SdkError) {
    return NextResponse.json(
      { error: e.code, error_description: e.message },
      { status: 400 }
    );
  }
  return serverError();
}

function serverError(): NextResponse {
  return NextResponse.json(
    { error: "server_error", error_description: "Internal server error" },
    { status: 500 }
  );
}

function invalidConnection(): NextResponse {
  return NextResponse.json(
    {
      error: "invalid_connection",
      error_description: "connection must be 'email' or 'sms'"
    },
    { status: 400 }
  );
}
