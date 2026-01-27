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
import type { AuthClient } from "../auth-client.js";

/**
 * Server-side MFA API.
 * Delegates all operations to AuthClient business logic.
 * Provides overload support for App Router and Pages Router.
 */
export class ServerMfaClient implements MfaClient {
  constructor(private authClient: AuthClient) {}

  /**
   * List enrolled MFA authenticators.
   *
   * @param options - Options containing encrypted mfaToken
   * @returns Array of authenticators filtered by mfa_requirements
   */
  async getAuthenticators(options: {
    mfaToken: string;
  }): Promise<Authenticator[]> {
    return this.authClient.mfaGetAuthenticators(options.mfaToken);
  }

  /**
   * Initiate an MFA challenge.
   *
   * @param options - Challenge options
   * @returns Challenge response (oobCode, bindingMethod)
   */
  async challenge(options: {
    mfaToken: string;
    challengeType: string;
    authenticatorId?: string;
  }): Promise<ChallengeResponse> {
    return this.authClient.mfaChallenge(
      options.mfaToken,
      options.challengeType,
      options.authenticatorId
    );
  }

  /**
   * Delete an enrolled MFA authenticator.
   *
   * @param options - Delete options containing encrypted mfaToken and authenticatorId
   * @returns Promise that resolves when deletion succeeds
   */
  async deleteAuthenticator(options: {
    mfaToken: string;
    authenticatorId: string;
  }): Promise<void> {
    return this.authClient.mfaDeleteAuthenticator(
      options.mfaToken,
      options.authenticatorId
    );
  }

  /**
   * Enroll a new MFA authenticator.
   *
   * @param options - Enrollment options (otp | oob | email)
   * @returns Enrollment response with authenticator details and optional recovery codes
   */
  async enroll(options: EnrollOptions): Promise<EnrollmentResponse> {
    const { mfaToken, ...enrollOptions } = options;
    return this.authClient.mfaEnroll(mfaToken, enrollOptions);
  }

  /**
   * Verify MFA code and complete authentication.
   * App Router overload (uses cookies() internally).
   *
   * @param options - Verification options
   * @returns Token response
   */
  async verify(options: VerifyMfaOptions): Promise<MfaVerifyResponse>;

  /**
   * Verify MFA code and complete authentication.
   * Pages Router/Middleware overload (explicit req/res).
   *
   * @param req - Next.js request
   * @param res - Next.js response
   * @param options - Verification options
   * @returns Token response
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
    // Determine which overload based on arg types
    if (arg1 instanceof NextRequest) {
      // Pages Router/Middleware: verify(req, res, options)
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      // Extract cookies from req/res and delegate
      return this.authClient.mfaVerify(arg3, arg1.cookies, arg2.cookies);
    } else {
      // App Router: verify(options)
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "verify(options): Only one argument allowed for App Router"
        );
      }
      // Get cookies from next/headers and delegate
      const { cookies } = await import("next/headers.js");
      const cookieStore = await cookies();
      return this.authClient.mfaVerify(
        arg1,
        cookieStore as any,
        cookieStore as any
      );
    }
  }
}
