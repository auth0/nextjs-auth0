import { cookies as getCookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";

import type {
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyClient,
  PasskeyEnrollmentChallengeOptions,
  PasskeyEnrollmentChallengeResponse,
  PasskeyEnrollmentVerifyOptions,
  PasskeyEnrollmentVerifyResponse,
  PasskeyGetTokenOptions,
  PasskeyRegisterOptions,
  PasskeyRegisterResponse
} from "../../types/index.js";
import type { AuthClientProvider } from "../auth-client-provider.js";
import type { AuthClient } from "../auth-client.js";

/**
 * Server-side passkey authentication API.
 * Delegates all operations to AuthClient business logic.
 * Provides overload support for App Router and Pages Router.
 *
 * Authentication flow (signup / login):
 * 1. Call register() or challenge() to get the WebAuthn options.
 * 2. In the browser: pass authnParamsPublicKey to navigator.credentials.create/get().
 * 3. Call getToken() with authSession + serialised credential to create the session.
 *
 * @example App Router — signup
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const challenge = await auth0.passkey.register();
 *   return NextResponse.json(challenge);
 * }
 * ```
 *
 * @example App Router — getToken
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { authSession, authResponse } = await req.json();
 *   await auth0.passkey.getToken({ authSession, authResponse });
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
  // register
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async register(
    options?: PasskeyRegisterOptions
  ): Promise<PasskeyRegisterResponse>;

  /** Pages Router / Middleware overload. */
  async register(
    req: NextRequest,
    options?: PasskeyRegisterOptions
  ): Promise<PasskeyRegisterResponse>;

  async register(
    arg1?: PasskeyRegisterOptions | NextRequest,
    arg2?: PasskeyRegisterOptions
  ): Promise<PasskeyRegisterResponse> {
    if (arg1 instanceof NextRequest) {
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyRegister(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passkeyRegister(arg1);
  }

  // ---------------------------------------------------------------------------
  // challenge
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async challenge(
    options?: PasskeyChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /** Pages Router / Middleware overload. */
  async challenge(
    req: NextRequest,
    options?: PasskeyChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  async challenge(
    arg1?: PasskeyChallengeOptions | NextRequest,
    arg2?: PasskeyChallengeOptions
  ): Promise<PasskeyChallengeResponse> {
    if (arg1 instanceof NextRequest) {
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyChallenge(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passkeyChallenge(arg1);
  }

  // ---------------------------------------------------------------------------
  // getToken
  // ---------------------------------------------------------------------------

  /** App Router overload — reads and writes cookies from next/headers. */
  async getToken(options: PasskeyGetTokenOptions): Promise<void>;

  /** Pages Router / Middleware overload — explicit req/res. */
  async getToken(
    req: NextRequest,
    res: NextResponse,
    options: PasskeyGetTokenOptions
  ): Promise<void>;

  async getToken(
    arg1: PasskeyGetTokenOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: PasskeyGetTokenOptions
  ): Promise<void> {
    if (arg1 instanceof NextRequest) {
      if (!arg2 || !arg3) {
        throw new TypeError(
          "getToken(req, res, options): All three arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      await authClient.passkeyGetToken(arg3, arg1.cookies, arg2.cookies);
    } else {
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "getToken(options): Only one argument allowed for App Router"
        );
      }
      const authClient = await this.getAuthClient();
      const cookiesLib = await getCookies();
      await authClient.passkeyGetToken(arg1, cookiesLib, cookiesLib);
    }
  }

  // ---------------------------------------------------------------------------
  // enrollmentChallenge
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async enrollmentChallenge(
    options?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse>;

  /** Pages Router / Middleware overload. */
  async enrollmentChallenge(
    req: NextRequest,
    options?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse>;

  async enrollmentChallenge(
    arg1?: PasskeyEnrollmentChallengeOptions | NextRequest,
    arg2?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse> {
    if (arg1 instanceof NextRequest) {
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyEnrollmentChallenge(arg1.cookies, arg2);
    }
    const authClient = await this.getAuthClient();
    const cookiesLib = await getCookies();
    return authClient.passkeyEnrollmentChallenge(cookiesLib as any, arg1);
  }

  // ---------------------------------------------------------------------------
  // enrollmentVerify
  // ---------------------------------------------------------------------------

  /** App Router overload. */
  async enrollmentVerify(
    options: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse>;

  /** Pages Router / Middleware overload. */
  async enrollmentVerify(
    req: NextRequest,
    options: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse>;

  async enrollmentVerify(
    arg1: PasskeyEnrollmentVerifyOptions | NextRequest,
    arg2?: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse> {
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "enrollmentVerify(req, options): Both arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passkeyEnrollmentVerify(arg2, arg1.cookies);
    }
    const authClient = await this.getAuthClient();
    const cookiesLib = await getCookies();
    return authClient.passkeyEnrollmentVerify(arg1, cookiesLib as any);
  }
}
