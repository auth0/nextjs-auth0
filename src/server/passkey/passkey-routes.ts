import { NextRequest, NextResponse } from "next/server.js";

import {
  MfaRequiredError,
  PasskeyChallengeError,
  PasskeyEnrollmentChallengeError,
  PasskeyEnrollmentVerifyError,
  PasskeyGetTokenError,
  PasskeyRegisterError,
  SdkError
} from "../../errors/index.js";
import type {
  PasskeyChallengeOptions,
  PasskeyEnrollmentChallengeOptions,
  PasskeyGetTokenOptions,
  PasskeyRegisterOptions
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
  challengePasskey,
  enrollmentChallenge,
  enrollmentVerify,
  getPasskeyToken,
  registerPasskey
} from "./passkey-operations.js";

// Copied from the body when truthy, as on nextjs.
const REGISTER_FIELDS = [
  "email",
  "username",
  "phoneNumber",
  "name",
  "givenName",
  "familyName",
  "nickname",
  "picture",
  "userMetadata",
  "connection",
  "organization"
] as const;

/**
 * Route: POST /auth/passkey/register, body `PasskeyRegisterOptions`. 200 with the challenge.
 */
export async function handlePasskeyRegister(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const options: Record<string, unknown> = {};
    for (const field of REGISTER_FIELDS) {
      if (body[field]) options[field] = body[field];
    }
    const { ctx } = await readContext(req);
    const challenge = await registerPasskey(
      setup,
      ctx,
      options as PasskeyRegisterOptions
    );
    return NextResponse.json(challenge);
  } catch (e) {
    return challengeErrorResponse(e, PasskeyRegisterError);
  }
}

/**
 * Route: POST /auth/passkey/challenge, body `{ connection?, organization? }`. 200 with the
 * challenge.
 */
export async function handlePasskeyChallenge(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const options: PasskeyChallengeOptions = {};
    if (typeof body.connection === "string")
      options.connection = body.connection;
    if (typeof body.organization === "string")
      options.organization = body.organization;
    const { ctx } = await readContext(req);
    const challenge = await challengePasskey(setup, ctx, options);
    return NextResponse.json(challenge);
  } catch (e) {
    return challengeErrorResponse(e, PasskeyChallengeError);
  }
}

/**
 * Route: POST /auth/passkey/token, body `{ authSession, authResponse, connection?, organization? }`.
 * The engine saves the session; 200 with `{ success: true }`, the session cookie and no-cache
 * headers. MFA required: 403 with the sealed token. Other `PasskeyGetTokenError`s: 403, except
 * `discovery_error` and `unexpected_error` (500).
 */
export async function handlePasskeyGetToken(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const authSession = validateStringFieldAndThrow(
      body.authSession,
      "authSession"
    );
    if (!body.authResponse || typeof body.authResponse !== "object") {
      return authResponseRequired();
    }
    const options: PasskeyGetTokenOptions = {
      authSession,
      authResponse: body.authResponse
    };
    if (typeof body.connection === "string")
      options.connection = body.connection;
    if (typeof body.organization === "string")
      options.organization = body.organization;

    const scratch = NextResponse.next();
    await getPasskeyToken(setup, middlewareContext(req, scratch), options);

    const res = NextResponse.json({ success: true });
    transferCookies(scratch, res);
    addCacheControlHeadersForSession(res);
    return res;
  } catch (e) {
    if (e instanceof MfaRequiredError) {
      // `#createMfaRequiredResponse` with no session: nothing to save.
      const res = NextResponse.json(e.toJSON(), { status: 403 });
      addCacheControlHeadersForSession(res);
      return res;
    }
    if (e instanceof PasskeyGetTokenError) {
      if (e.error === "discovery_error" || e.error === "unexpected_error") {
        return serverError();
      }
      return NextResponse.json(e.toJSON(), { status: 403 });
    }
    return otherErrorResponse(e);
  }
}

/**
 * Route: POST /auth/passkey/enrollment/challenge, body `{ connection?, userIdentityId? }`. Needs a
 * session; 200 with the challenge. A refreshed MyAccount token is saved (D6).
 */
export async function handlePasskeyEnrollmentChallenge(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const options: PasskeyEnrollmentChallengeOptions = {};
    if (typeof body.connection === "string")
      options.connection = body.connection;
    if (typeof body.userIdentityId === "string")
      options.userIdentityId = body.userIdentityId;

    const scratch = NextResponse.next();
    const challenge = await enrollmentChallenge(
      setup,
      middlewareContext(req, scratch),
      options
    );
    const res = NextResponse.json(challenge);
    transferCookies(scratch, res);
    return res;
  } catch (e) {
    return enrollmentErrorResponse(e, PasskeyEnrollmentChallengeError);
  }
}

/**
 * Route: POST /auth/passkey/enrollment/verify, body `{ authenticationMethodId, authSession,
 * authResponse }`. Needs a session; 200 with Auth0's body. A refreshed MyAccount token is saved
 * (D6).
 */
export async function handlePasskeyEnrollmentVerify(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const authenticationMethodId = validateStringFieldAndThrow(
      body.authenticationMethodId,
      "authenticationMethodId"
    );
    const authSession = validateStringFieldAndThrow(
      body.authSession,
      "authSession"
    );
    if (!body.authResponse || typeof body.authResponse !== "object") {
      return authResponseRequired();
    }

    const scratch = NextResponse.next();
    const result = await enrollmentVerify(
      setup,
      middlewareContext(req, scratch),
      { authenticationMethodId, authSession, authResponse: body.authResponse }
    );
    const res = NextResponse.json(result);
    transferCookies(scratch, res);
    return res;
  } catch (e) {
    return enrollmentErrorResponse(e, PasskeyEnrollmentVerifyError);
  }
}

// Register and challenge: `unexpected_error` 500, other errors of the class 400.
function challengeErrorResponse(
  e: unknown,
  ErrorClass: typeof PasskeyRegisterError | typeof PasskeyChallengeError
): NextResponse {
  if (e instanceof ErrorClass) {
    if (e.error === "unexpected_error") {
      return serverError();
    }
    return NextResponse.json(e.toJSON(), { status: 400 });
  }
  return otherErrorResponse(e);
}

// Enrollment: `not_authenticated` and `token_error` 401, `unexpected_error` 500, others 400.
function enrollmentErrorResponse(
  e: unknown,
  ErrorClass:
    typeof PasskeyEnrollmentChallengeError | typeof PasskeyEnrollmentVerifyError
): NextResponse {
  if (e instanceof ErrorClass) {
    if (e.error === "not_authenticated" || e.error === "token_error") {
      return NextResponse.json(e.toJSON(), { status: 401 });
    }
    if (e.error === "unexpected_error") {
      return serverError();
    }
    return NextResponse.json(e.toJSON(), { status: 400 });
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

function authResponseRequired(): NextResponse {
  return NextResponse.json(
    { error: "invalid_request", error_description: "authResponse is required" },
    { status: 400 }
  );
}
