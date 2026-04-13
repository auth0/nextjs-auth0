import { cookies as getCookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";

import type {
  PasswordlessClient,
  PasswordlessStartOptions,
  PasswordlessVerifyOptions
} from "../../types/index.js";
import type { AuthClientProvider } from "../auth-client-provider.js";
import type { AuthClient } from "../auth-client.js";

/**
 * Server-side passwordless authentication API.
 * Delegates all operations to AuthClient business logic.
 * Provides overload support for App Router and Pages Router.
 *
 * @example App Router — start
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { connection, email, send } = await req.json();
 *   await auth0.passwordless.start({ connection, email, send });
 *   return new Response(null, { status: 204 });
 * }
 * ```
 *
 * @example App Router — verify
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { connection, email, verificationCode } = await req.json();
 *   await auth0.passwordless.verify({ connection, email, verificationCode });
 *   return new Response(null, { status: 204 });
 * }
 * ```
 */
export class ServerPasswordlessClient implements PasswordlessClient {
  constructor(private provider: AuthClientProvider) {}

  private async getAuthClient(): Promise<AuthClient> {
    const { headers } = await import("next/headers.js");
    const reqHeaders = await headers();
    return this.provider.forRequest(reqHeaders, undefined);
  }

  /**
   * Initiate a passwordless flow by sending an OTP to the user's email or phone.
   *
   * @param options - Connection type and user identifier (email or phone)
   */
  async start(options: PasswordlessStartOptions): Promise<void> {
    const authClient = await this.getAuthClient();
    return authClient.passwordlessStart(options);
  }

  /**
   * Verify a passwordless OTP and establish a session.
   * App Router overload — reads and writes cookies from `next/headers`.
   *
   * @param options - Connection type, user identifier, and verification code
   */
  async verify(options: PasswordlessVerifyOptions): Promise<void>;

  /**
   * Verify a passwordless OTP and establish a session.
   * Pages Router / Middleware overload — explicit req/res.
   *
   * @param req - Next.js request
   * @param res - Next.js response
   * @param options - Connection type, user identifier, and verification code
   */
  async verify(
    req: NextRequest,
    res: NextResponse,
    options: PasswordlessVerifyOptions
  ): Promise<void>;

  async verify(
    arg1: PasswordlessVerifyOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: PasswordlessVerifyOptions
  ): Promise<void> {
    const authClient = await this.getAuthClient();

    if (arg1 instanceof NextRequest) {
      // Pages Router / Middleware: verify(req, res, options)
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      const tokenResponse = await authClient.passwordlessVerify(arg3);
      await authClient.createSessionFromPasswordlessVerify(
        tokenResponse,
        arg1.cookies,
        arg2.cookies
      );
    } else {
      // App Router: verify(options)
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "verify(options): Only one argument allowed for App Router"
        );
      }
      const tokenResponse = await authClient.passwordlessVerify(arg1);
      const cookiesLib = await getCookies();
      await authClient.createSessionFromPasswordlessVerify(
        tokenResponse,
        cookiesLib as any,
        cookiesLib as any
      );
    }
  }
}
