import { NextRequest, NextResponse } from "next/server.js";
import type {
  AuthenticatorResponse,
  ChallengeResponse as EngineChallengeResponse,
  EnrollmentResponse as EngineEnrollmentResponse
} from "@auth0/auth0-auth-js";

import type { VerifyMfaOptions } from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { buildEnrollOptions } from "../../utils/mfa-server-utils.js";
import { transformVerifyBodyToOptions } from "../../utils/mfa-transform-utils.js";
import { handleMfaError } from "../../utils/mfa-utils.js";
import {
  extractMfaToken,
  parseJsonBody,
  validateArrayFieldAndThrow,
  validateStringFieldAndThrow,
  validateVerificationCredentialAndThrow
} from "../../utils/mfa-validation-utils.js";
import { middlewareContext, readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import {
  challengeAuthenticator,
  enrollAuthenticator,
  listAuthenticators,
  toVerifyResponse,
  verifyMfa
} from "./mfa-operations.js";

/**
 * Route: GET /auth/mfa/authenticators, `Authorization: Bearer <encrypted mfa_token>`.
 * 200 with the snake_case list filtered by `mfa_requirements`; errors as `handleMfaError`.
 */
export async function handleMfaAuthenticators(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const mfaToken = extractMfaToken(req);
    const { ctx } = await readContext(req);
    const authenticators = await listAuthenticators(setup, ctx, mfaToken);
    return NextResponse.json(authenticators.map(toAuthenticatorBody));
  } catch (e) {
    return handleMfaError(e);
  }
}

/**
 * Route: POST /auth/mfa/challenge, body `{ mfa_token, challenge_type, authenticator_id? }`
 * (the token in the body, as Auth0's API takes it). 200 with the snake_case challenge.
 */
export async function handleMfaChallenge(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const body = (await parseJsonBody(req)) as Record<string, any>;
    const mfaToken = validateStringFieldAndThrow(body.mfa_token, "mfa_token");
    const challengeType = validateStringFieldAndThrow(
      body.challenge_type,
      "challenge_type"
    );
    const authenticatorId = body.authenticator_id
      ? validateStringFieldAndThrow(body.authenticator_id, "authenticator_id")
      : undefined;
    const { ctx } = await readContext(req);
    const result = await challengeAuthenticator(
      setup,
      ctx,
      mfaToken,
      challengeType,
      authenticatorId
    );
    return NextResponse.json(toChallengeBody(result));
  } catch (e) {
    return handleMfaError(e);
  }
}

/**
 * Route: POST /auth/mfa/associate, `Authorization: Bearer <encrypted mfa_token>`, body
 * `{ authenticator_types, oob_channels?, phone_number?, email? }` (snake_case only). 200 with
 * the snake_case enrollment.
 */
export async function handleMfaAssociate(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const mfaToken = extractMfaToken(req);
    const body = await parseJsonBody(req);
    const authenticatorTypes = validateArrayFieldAndThrow(
      (body as Record<string, any>).authenticator_types,
      "authenticator_types"
    );
    const [enrollOptions, errorResponse] = buildEnrollOptions(
      body,
      authenticatorTypes[0]
    );
    if (errorResponse) return errorResponse;

    const { ctx } = await readContext(req);
    const result = await enrollAuthenticator(
      setup,
      ctx,
      mfaToken,
      enrollOptions
    );
    return NextResponse.json(toEnrollmentBody(result));
  } catch (e) {
    return handleMfaError(e);
  }
}

/**
 * Route: POST /auth/mfa/verify, `Authorization: Bearer <encrypted mfa_token>`, body
 * `{ otp | oob_code + binding_code | recovery_code }` (snake_case only). The engine saves the
 * session (step-up, or a first login with no session); 200 with `{ success: true,
 * recovery_code? }`, the session cookie and no-cache headers. Tokens are never in the body.
 */
export async function handleMfaVerify(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  try {
    const mfaToken = extractMfaToken(req);
    const body = await parseJsonBody(req);
    validateVerificationCredentialAndThrow(body);
    const credential = transformVerifyBodyToOptions(
      body as Record<string, any>
    );

    const scratch = NextResponse.next();
    const result = await verifyMfa(setup, middlewareContext(req, scratch), {
      mfaToken,
      ...credential
    } as VerifyMfaOptions);

    const res = NextResponse.json(toVerifyResponse(result));
    transferCookies(scratch, res);
    addCacheControlHeadersForSession(res);
    return res;
  } catch (e) {
    return handleMfaError(e);
  }
}

// Auth0's field names, from the engine's.
function toAuthenticatorBody(auth: AuthenticatorResponse) {
  return {
    id: auth.id,
    authenticator_type: auth.authenticatorType,
    active: auth.active,
    name: auth.name,
    oob_channels: auth.oobChannels,
    type: auth.type
  };
}

function toChallengeBody(result: EngineChallengeResponse) {
  return {
    challenge_type: result.challengeType,
    oob_code: result.oobCode,
    binding_method: result.bindingMethod
  };
}

function toEnrollmentBody(result: EngineEnrollmentResponse) {
  if (result.authenticatorType === "otp") {
    return {
      authenticator_type: result.authenticatorType,
      secret: result.secret,
      barcode_uri: result.barcodeUri,
      recovery_codes: result.recoveryCodes,
      id: result.id
    };
  }
  return {
    authenticator_type: result.authenticatorType,
    oob_channel: result.oobChannel,
    oob_code: result.oobCode,
    binding_method: result.bindingMethod,
    id: result.id,
    barcode_uri: result.barcodeUri,
    recovery_codes: result.recoveryCodes
  };
}
