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

  private async getAuthClient(req?: NextRequest): Promise<AuthClient> {
    const { headers } = await import("next/headers.js");
    const reqHeaders = req ? req.headers : await headers();
    const url = req?.nextUrl;
    return this.provider.forRequest(reqHeaders, url);
  }

  /**
   * Initiate a passwordless flow by sending an OTP to the user's email or phone.
   * App Router overload — reads headers from `next/headers`.
   *
   * @param options - Connection type and user identifier (email or phone)
   */
  async start(options: PasswordlessStartOptions): Promise<void>;

  /**
   * Initiate a passwordless flow by sending an OTP to the user's email or phone.
   * Pages Router / Middleware overload — pass the request for Multi-Custom Domain resolution.
   *
   * @param req - Next.js request (provides URL context for MCD domain resolution)
   * @param options - Connection type and user identifier (email or phone)
   */
  async start(
    req: NextRequest,
    options: PasswordlessStartOptions
  ): Promise<void>;

  async start(
    arg1: PasswordlessStartOptions | NextRequest,
    arg2?: PasswordlessStartOptions
  ): Promise<void> {
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "start(req, options): options argument is required"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passwordlessStart(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passwordlessStart(arg1);
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
    if (arg1 instanceof NextRequest) {
      // Pages Router / Middleware: verify(req, res, options)
      // req is passed so MCD resolver can pick the correct Auth0 domain
      if (!arg2 || !arg3) {
        throw new TypeError(
          "verify(req, res, options): All three arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
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
      const authClient = await this.getAuthClient();
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
