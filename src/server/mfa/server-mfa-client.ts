import { NextRequest, NextResponse } from "next/server.js";
import type {
  AuthenticatorResponse,
  EnrollmentResponse as EngineEnrollmentResponse
} from "@auth0/auth0-auth-js";

import type {
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  EnrollOptions,
  MfaClient,
  MfaVerifyResponse,
  VerifyMfaOptions
} from "../../types/index.js";
import { normalizeEnrollOptions } from "../../utils/mfa-transform-utils.js";
import { withCallContext } from "../engine/call-context.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import {
  challengeAuthenticator,
  enrollAuthenticator,
  listAuthenticators,
  toVerifyResponse,
  verifyMfa
} from "./mfa-operations.js";

/**
 * Server-side MFA API.
 * Delegates all operations to AuthClient business logic.
 * Provides overload support for App Router and Pages Router.
 *
 * @example App Router
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { mfa } = auth0;
 *   const { mfaToken } = await req.json();
 *
 *   const authenticators = await mfa.getAuthenticators({ mfaToken });
 *   return Response.json(authenticators);
 * }
 * ```
 *
 * @example Pages Router
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export default async function handler(req, res) {
 *   const { mfa } = auth0;
 *   const { mfaToken } = req.body;
 *
 *   const authenticators = await mfa.getAuthenticators({ mfaToken });
 *   res.json(authenticators);
 * }
 * ```
 */
export class ServerMfaClient implements MfaClient {
  #setup: EngineSetup;

  /**
   * @internal Reached through `Auth0Client.mfa`.
   */
  constructor(setup: EngineSetup) {
    this.#setup = setup;
  }

  /**
   * List enrolled MFA authenticators.
   *
   * @param options - Options containing encrypted mfaToken
   * @returns Array of authenticators (camelCase SDK format) filtered by mfa_requirements
   *
   * @example App Router
   * ```typescript
   * // app/api/mfa/authenticators/route.ts
   * import { NextRequest, NextResponse } from "next/server";
   * import { auth0 } from "@/lib/auth0";
   *
   * export async function POST(req: NextRequest) {
   *   const { mfaToken } = await req.json();
   *   const authenticators = await auth0.mfa.getAuthenticators({ mfaToken });
   *   return NextResponse.json(authenticators);
   * }
   * ```
   *
   * @example Pages Router
   * ```typescript
   * // pages/api/mfa/authenticators.ts
   * import type { NextApiRequest, NextApiResponse } from "next";
   * import { auth0 } from "@/lib/auth0";
   *
   * export default async function handler(req: NextApiRequest, res: NextApiResponse) {
   *   const { mfaToken } = req.body;
   *   const authenticators = await auth0.mfa.getAuthenticators({ mfaToken });
   *   res.json(authenticators);
   * }
   * ```
   */
  async getAuthenticators(options: {
    mfaToken: string;
  }): Promise<Authenticator[]> {
    const { ctx } = await readContext();
    const authenticators = await listAuthenticators(
      this.#setup,
      ctx,
      options.mfaToken
    );
    return authenticators.map(toAuthenticator);
  }

  /**
   * Initiate an MFA challenge.
   *
   * @param options - Challenge options
   * @returns Challenge response (camelCase SDK format: challengeType, oobCode, bindingMethod)
   *
   * @example
   * ```typescript
   * // app/api/mfa/challenge/route.ts
   * const { mfaToken, authenticatorId } = await req.json();
   *
   * const challenge = await auth0.mfa.challenge({
   *   mfaToken,
   *   challengeType: "oob",
   *   authenticatorId
   * });
   *
   * return NextResponse.json({
   *   oobCode: challenge.oobCode,
   *   bindingMethod: challenge.bindingMethod
   * });
   * ```
   */
  async challenge(options: {
    mfaToken: string;
    challengeType: string;
    authenticatorId?: string;
  }): Promise<ChallengeResponse> {
    const { ctx } = await readContext();
    const result = await challengeAuthenticator(
      this.#setup,
      ctx,
      options.mfaToken,
      options.challengeType,
      options.authenticatorId
    );
    return {
      challengeType: result.challengeType,
      oobCode: result.oobCode,
      bindingMethod: result.bindingMethod
    };
  }

  /**
   * Enroll a new MFA authenticator.
   *
   * @param options - Enrollment options (otp | oob | email)
   * @returns Enrollment response (camelCase SDK format) with authenticator details and optional recovery codes
   *
   * @example OTP Enrollment
   * ```typescript
   * const enrollment = await auth0.mfa.enroll({
   *   mfaToken,
   *   authenticatorTypes: ["otp"]
   * });
   *
   * // Returns: { id, secret, barcodeUri, recoveryCodes }
   * ```
   *
   * @example SMS Enrollment
   * ```typescript
   * const enrollment = await auth0.mfa.enroll({
   *   mfaToken,
   *   authenticatorTypes: ["oob"],
   *   oobChannels: ["sms"],
   *   phoneNumber: "+15551234567"
   * });
   *
   * // Returns: { id, oobChannel, name, recoveryCodes }
   * ```
   */
  async enroll(options: EnrollOptions): Promise<EnrollmentResponse> {
    // `factorType` variants to the `authenticatorTypes` form, checked before the token.
    const { mfaToken, ...enrollOptions } = normalizeEnrollOptions(options);
    const { ctx } = await readContext();
    const result = await enrollAuthenticator(
      this.#setup,
      ctx,
      mfaToken,
      enrollOptions
    );
    return toEnrollmentResponse(result);
  }

  /**
   * Verify MFA code and complete authentication.
   * App Router overload (uses cookies() internally).
   *
   * Stores resulting tokens in the session cookie. Returns `{ success: true }`.
   * Call `getAccessToken()` after verify to retrieve the token.
   *
   * @param options - Verification options
   * @returns `{ success: true }`
   */
  async verify(options: VerifyMfaOptions): Promise<MfaVerifyResponse>;

  /**
   * Verify MFA code and complete authentication.
   * Pages Router/Middleware overload (explicit req/res).
   *
   * Stores resulting tokens in the session cookie. Returns `{ success: true }`.
   * Call `getAccessToken()` after verify to retrieve the token.
   *
   * @param req - Next.js request
   * @param res - Next.js response
   * @param options - Verification options
   * @returns `{ success: true }`
   */
  async verify(
    req: NextRequest,
    res: NextResponse,
    options: VerifyMfaOptions
  ): Promise<MfaVerifyResponse>;

  /**
   * Implementation with overload resolution.
   * Resolves cookies and delegates to AuthClient for business logic + session management.
   */
  async verify(
    arg1: VerifyMfaOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: VerifyMfaOptions
  ): Promise<MfaVerifyResponse> {
    let req: NextRequest | undefined;
    let res: NextResponse | undefined;
    let options: VerifyMfaOptions;
    if (arg1 instanceof NextRequest) {
      // Middleware: verify(req, res, options); the session is written to `res`.
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      [req, res, options] = [arg1, arg2, arg3];
    } else {
      // App Router: verify(options); the session is written to `cookies()`.
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "verify(options): Only one argument allowed for App Router"
        );
      }
      options = arg1;
    }

    // A write Next refuses (a Server Component) throws, as on nextjs: the code is already spent.
    const result = await withCallContext(
      req,
      res,
      (ctx) =>
        verifyMfa(this.#setup, ctx, options, { checkSessionDomain: true }),
      { ignoreWriteErrors: false }
    );
    return toVerifyResponse(result);
  }
}

/**
 * nextjs's authenticator shape from the engine's fields. Auth0's docs name the channel
 * `oob_channels` and type it as a string; the engine types it as a list, so both are read.
 */
function toAuthenticator(auth: AuthenticatorResponse): Authenticator {
  const channels = auth.oobChannels as string[] | string | undefined;
  return {
    id: auth.id,
    authenticatorType: auth.authenticatorType,
    type: auth.type,
    active: auth.active,
    name: auth.name,
    oobChannel: Array.isArray(channels) ? channels[0] : channels
  };
}

/**
 * nextjs's enrollment shape from the engine's fields.
 */
function toEnrollmentResponse(
  result: EngineEnrollmentResponse
): EnrollmentResponse {
  if (result.authenticatorType === "otp") {
    return {
      authenticatorType: "otp",
      id: result.id as string,
      recoveryCodes: result.recoveryCodes,
      secret: result.secret,
      barcodeUri: result.barcodeUri
    };
  }
  return {
    authenticatorType: "oob",
    id: result.id as string,
    recoveryCodes: result.recoveryCodes,
    oobChannel: result.oobChannel,
    oobCode: result.oobCode,
    bindingMethod: result.bindingMethod,
    barcodeUri: result.barcodeUri
  };
}
