import { NextRequest, NextResponse } from "next/server.js";

import type {
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  EnrollOptions,
  MfaClient,
  MfaVerifyResponse,
  VerifyMfaOptions
} from "../../types/index.js";

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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
  }
}
