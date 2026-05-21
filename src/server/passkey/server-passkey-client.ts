import { cookies as getCookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";

import type {
  PasskeyAuthenticationMethod,
  PasskeyChallengeResponse,
  PasskeyClient,
  PasskeyEnrollmentChallengeResponse,
  PasskeyEnrollVerifyOptions,
  PasskeyLoginChallengeOptions,
  PasskeySignupChallengeOptions,
  PasskeyVerifyOptions
} from "../../types/index.js";
import type { AuthClientProvider } from "../auth-client-provider.js";
import type { AuthClient } from "../auth-client.js";

/**
 * Server-side passkey authentication API.
 * Delegates all operations to AuthClient business logic.
 * Provides overload support for App Router and Pages Router.
 *
 * Authentication flow (signup / login):
 * 1. Call signupChallenge() or loginChallenge() to get the WebAuthn options.
 * 2. In the browser: pass authnParamsPublicKey to navigator.credentials.create/get().
 * 3. Call verify() with authSession + serialised credential to create the session.
 *
 * Enrollment flow (add passkey to an existing authenticated account):
 * 1. Call enrollmentChallenge() to get the WebAuthn creation options.
 * 2. In the browser: pass authnParamsPublicKey to navigator.credentials.create().
 * 3. Call enrollVerify() with authenticationMethodId + authSession + credential.
 *
 * @example App Router — signup
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const challenge = await auth0.passkey.signupChallenge();
 *   return NextResponse.json(challenge);
 * }
 * ```
 *
 * @example App Router — verify
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { authSession, authResponse } = await req.json();
 *   await auth0.passkey.verify({ authSession, authResponse });
 *   return new Response(null, { status: 204 });
 * }
 * ```
 */
export class ServerPasskeyClient implements PasskeyClient {
  constructor(private provider: AuthClientProvider) {}

  private async getAuthClient(req?: NextRequest): Promise<AuthClient> {
    const { headers } = await import("next/headers.js");
    const reqHeaders = req ? req.headers : await headers();
    const url = req?.nextUrl;
    return this.provider.forRequest(reqHeaders, url);
  }

  // ---------------------------------------------------------------------------
  // signupChallenge
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async signupChallenge(
    options?: PasskeySignupChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /** Pages Router / Middleware overload. */
  async signupChallenge(
    req: NextRequest,
    options?: PasskeySignupChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  async signupChallenge(
    arg1?: PasskeySignupChallengeOptions | NextRequest,
    arg2?: PasskeySignupChallengeOptions
  ): Promise<PasskeyChallengeResponse> {
    if (arg1 instanceof NextRequest) {
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeySignupChallenge(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passkeySignupChallenge(arg1);
  }

  // ---------------------------------------------------------------------------
  // loginChallenge
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async loginChallenge(
    options?: PasskeyLoginChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /** Pages Router / Middleware overload. */
  async loginChallenge(
    req: NextRequest,
    options?: PasskeyLoginChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  async loginChallenge(
    arg1?: PasskeyLoginChallengeOptions | NextRequest,
    arg2?: PasskeyLoginChallengeOptions
  ): Promise<PasskeyChallengeResponse> {
    if (arg1 instanceof NextRequest) {
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyLoginChallenge(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passkeyLoginChallenge(arg1);
  }

  // ---------------------------------------------------------------------------
  // verify
  // ---------------------------------------------------------------------------

  /** App Router overload — reads and writes cookies from next/headers. */
  async verify(options: PasskeyVerifyOptions): Promise<void>;

  /** Pages Router / Middleware overload — explicit req/res. */
  async verify(
    req: NextRequest,
    res: NextResponse,
    options: PasskeyVerifyOptions
  ): Promise<void>;

  async verify(
    arg1: PasskeyVerifyOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: PasskeyVerifyOptions
  ): Promise<void> {
    if (arg1 instanceof NextRequest) {
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      await authClient.passkeyVerify(arg3, arg1.cookies, arg2.cookies);
    } else {
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "verify(options): Only one argument allowed for App Router"
        );
      }
      const authClient = await this.getAuthClient();
      const cookiesLib = await getCookies();
      await authClient.passkeyVerify(
        arg1,
        cookiesLib as any,
        cookiesLib as any
      );
    }
  }

  // ---------------------------------------------------------------------------
  // enrollmentChallenge
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async enrollmentChallenge(): Promise<PasskeyEnrollmentChallengeResponse>;

  /** Pages Router / Middleware overload. */
  async enrollmentChallenge(
    req: NextRequest
  ): Promise<PasskeyEnrollmentChallengeResponse>;

  async enrollmentChallenge(
    req?: NextRequest
  ): Promise<PasskeyEnrollmentChallengeResponse> {
    const authClient = await this.getAuthClient(req);
    return authClient.passkeyEnrollmentChallenge(req);
  }

  // ---------------------------------------------------------------------------
  // enrollVerify
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async enrollVerify(
    options: PasskeyEnrollVerifyOptions
  ): Promise<PasskeyAuthenticationMethod>;

  /** Pages Router / Middleware overload. */
  async enrollVerify(
    req: NextRequest,
    options: PasskeyEnrollVerifyOptions
  ): Promise<PasskeyAuthenticationMethod>;

  async enrollVerify(
    arg1: PasskeyEnrollVerifyOptions | NextRequest,
    arg2?: PasskeyEnrollVerifyOptions
  ): Promise<PasskeyAuthenticationMethod> {
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "enrollVerify(req, options): options argument is required"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyEnrollVerify(arg2, arg1);
    }
    const authClient = await this.getAuthClient();
    return authClient.passkeyEnrollVerify(arg1);
  }
}
