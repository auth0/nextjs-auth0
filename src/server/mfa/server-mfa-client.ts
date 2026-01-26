import { NextRequest, NextResponse } from "next/server.js";
import type { AuthClient } from "../auth-client.js";
import type { RequestCookies, ResponseCookies } from "../cookies.js";
import { AccessTokenErrorCode, MfaVerifyError } from "../../errors/index.js";
import type {
  MfaClient,
  Authenticator,
  ChallengeResponse,
  MfaVerifyResponse,
  VerifyMfaOptions
} from "../../types/index.js";

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
   * Handles session management and delegates business logic to AuthClient.
   */
  async verify(
    arg1: VerifyMfaOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: VerifyMfaOptions
  ): Promise<MfaVerifyResponse> {
    let reqCookies: RequestCookies;
    let resCookies: ResponseCookies;
    let options: VerifyMfaOptions;

    // Determine which overload based on arg types
    if (arg1 instanceof NextRequest) {
      // Pages Router/Middleware: verify(req, res, options)
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      reqCookies = arg1.cookies;
      resCookies = arg2.cookies;
      options = arg3;
    } else {
      // App Router: verify(options)
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "verify(options): Only one argument allowed for App Router"
        );
      }
      const { cookies } = await import("next/headers.js");
      const cookieStore = await cookies();
      reqCookies = cookieStore as any;
      resCookies = cookieStore as any;
      options = arg1;
    }

    // Get session for token caching
    const session = await (this.authClient as any).sessionStore.get(reqCookies);
    if (!session) {
      throw new MfaVerifyError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    // Call AuthClient business logic
    const response = await this.authClient.mfaVerify(options);

    // Cache access token in session
    session.accessTokens = session.accessTokens || [];
    session.accessTokens.push({
      accessToken: response.access_token,
      scope: response.scope,
      audience: response.audience,
      expiresAt: Math.floor(Date.now() / 1000) + Number(response.expires_in),
      token_type: response.token_type
    });

    await (this.authClient as any).sessionStore.save(session, reqCookies, resCookies);

    return response;
  }
}
