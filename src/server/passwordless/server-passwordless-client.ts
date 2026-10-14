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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
  }
}
