import { cookies as getCookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";

import type {
  PasswordlessClient,
  PasswordlessDbChallenge,
  PasswordlessDbChallengeEmailOptions,
  PasswordlessDbChallengePhoneOptions,
  PasswordlessDbGetTokenOptions,
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
 * @example App Router — OTP start
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
 * @example App Router — magic link start
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 *
 * export async function POST(req: NextRequest) {
 *   const { email } = await req.json();
 *   // Transaction cookie written to next/headers automatically
 *   await auth0.passwordless.start({ connection: 'email', email, send: 'link' });
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
   * Initiate a passwordless flow by sending an OTP or magic link to the user's email or phone.
   * App Router overload — reads headers from `next/headers`.
   * For magic link (`send: 'link'`), the transaction cookie is written via `next/headers` automatically.
   *
   * @param options - Connection type and user identifier (email or phone)
   */
  async start(options: PasswordlessStartOptions): Promise<void>;

  /**
   * Initiate a passwordless flow by sending an OTP or magic link to the user's email or phone.
   * Pages Router overload — explicit req/res for cookie and MCD domain resolution.
   * For magic link (`send: 'link'`), the transaction cookie is written to `res`.
   *
   * @param req - Next.js request (provides URL context for MCD domain resolution)
   * @param res - Next.js response (receives the transaction cookie for magic link)
   * @param options - Connection type and user identifier (email or phone)
   */
  async start(
    req: NextRequest,
    res: NextResponse,
    options: PasswordlessStartOptions
  ): Promise<void>;

  async start(
    arg1: PasswordlessStartOptions | NextRequest,
    arg2?: NextResponse | PasswordlessStartOptions,
    arg3?: PasswordlessStartOptions
  ): Promise<void> {
    // Pages Router: start(req, res, options)
    if (arg1 instanceof NextRequest) {
      if (!(arg2 instanceof NextResponse) || !arg3) {
        throw new TypeError(
          "start(req, res, options): All three arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passwordlessStart(arg3, arg2.cookies, arg1);
    }

    // App Router: start(options)
    // Only read next/headers cookies for magic link — OTP flows don't write cookies.
    const authClient = await this.getAuthClient();
    const isMagicLink = arg1.connection === "email" && arg1.send === "link";
    // `as any`: ReadonlyRequestCookies is typed as Omit<RequestCookies, 'set'|'clear'|'delete'>
    // & Pick<ResponseCookies, 'set'|'delete'>, so it does expose .set() at runtime despite
    // the name. The cast suppresses the TS mismatch against the ResponseCookies parameter type.
    const cookiesLib = isMagicLink ? await getCookies() : undefined;
    return authClient.passwordlessStart(arg1, cookiesLib as any);
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

  /**
   * Request an OTP challenge for a database connection user identified by email.
   * App Router overload — reads headers from `next/headers`.
   */
  async challengeWithEmail(
    options: PasswordlessDbChallengeEmailOptions
  ): Promise<PasswordlessDbChallenge>;

  /**
   * Request an OTP challenge for a database connection user identified by email.
   * Pages Router overload — explicit req for MCD domain resolution.
   */
  async challengeWithEmail(
    req: NextRequest,
    options: PasswordlessDbChallengeEmailOptions
  ): Promise<PasswordlessDbChallenge>;

  async challengeWithEmail(
    arg1: PasswordlessDbChallengeEmailOptions | NextRequest,
    arg2?: PasswordlessDbChallengeEmailOptions
  ): Promise<PasswordlessDbChallenge> {
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "challengeWithEmail(req, options): Both arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passwordlessDbOtpChallenge(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passwordlessDbOtpChallenge(arg1);
  }

  /**
   * Request an OTP challenge for a database connection user identified by phone number.
   * App Router overload — reads headers from `next/headers`.
   */
  async challengeWithPhoneNumber(
    options: PasswordlessDbChallengePhoneOptions
  ): Promise<PasswordlessDbChallenge>;

  /**
   * Request an OTP challenge for a database connection user identified by phone number.
   * Pages Router overload — explicit req for MCD domain resolution.
   */
  async challengeWithPhoneNumber(
    req: NextRequest,
    options: PasswordlessDbChallengePhoneOptions
  ): Promise<PasswordlessDbChallenge>;

  async challengeWithPhoneNumber(
    arg1: PasswordlessDbChallengePhoneOptions | NextRequest,
    arg2?: PasswordlessDbChallengePhoneOptions
  ): Promise<PasswordlessDbChallenge> {
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "challengeWithPhoneNumber(req, options): Both arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      return authClient.passwordlessDbOtpChallenge(arg2);
    }
    const authClient = await this.getAuthClient();
    return authClient.passwordlessDbOtpChallenge(arg1);
  }

  /**
   * Exchange an auth_session + OTP for tokens and establish a session.
   * App Router overload — reads and writes cookies from `next/headers`.
   */
  async loginWithOtp(options: PasswordlessDbGetTokenOptions): Promise<void>;

  /**
   * Exchange an auth_session + OTP for tokens and establish a session.
   * Pages Router overload — explicit req/res for cookie handling.
   */
  async loginWithOtp(
    req: NextRequest,
    res: NextResponse,
    options: PasswordlessDbGetTokenOptions
  ): Promise<void>;

  async loginWithOtp(
    arg1: PasswordlessDbGetTokenOptions | NextRequest,
    arg2?: NextResponse,
    arg3?: PasswordlessDbGetTokenOptions
  ): Promise<void> {
    if (arg1 instanceof NextRequest) {
      if (!arg2 || !arg3) {
        throw new TypeError(
          "loginWithOtp(req, res, options): All three arguments required for Pages Router"
        );
      }
      const authClient = await this.getAuthClient(arg1);
      const tokenResponse = await authClient.passwordlessDbGetToken(arg3);
      await authClient.createSessionFromPasswordlessVerify(
        tokenResponse,
        arg1.cookies,
        arg2.cookies
      );
      return;
    }
    const authClient = await this.getAuthClient();
    const tokenResponse = await authClient.passwordlessDbGetToken(arg1);
    const cookiesLib = await getCookies();
    await authClient.createSessionFromPasswordlessVerify(
      tokenResponse,
      cookiesLib as any,
      cookiesLib as any
    );
  }
}
