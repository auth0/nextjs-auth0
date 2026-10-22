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
import { withCallContext } from "../engine/call-context.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import {
  challengeDbConnection,
  loginWithDbOtp,
  startPasswordless,
  verifyPasswordless
} from "./passwordless-operations.js";

/**
 * Server-side passwordless authentication API.
 * The engine sends the start, challenge and token requests and saves the session; a magic link is
 * completed by the callback route.
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
  #setup: EngineSetup;

  /**
   * @internal Reached through `Auth0Client.passwordless`.
   */
  constructor(setup: EngineSetup) {
    this.#setup = setup;
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
    let req: NextRequest | undefined;
    let res: NextResponse | undefined;
    let options: PasswordlessStartOptions;
    if (arg1 instanceof NextRequest) {
      // Pages Router: start(req, res, options); a magic link's transaction is written to `res`.
      if (!(arg2 instanceof NextResponse) || !arg3) {
        throw new TypeError(
          "start(req, res, options): All three arguments required for Pages Router"
        );
      }
      [req, res, options] = [arg1, arg2, arg3];
    } else {
      // App Router: start(options); a magic link's transaction is written to `cookies()`.
      options = arg1;
    }

    // A write Next refuses (a Server Component) throws, as on nextjs: the link would not work.
    await withCallContext(
      req,
      res,
      (ctx) => startPasswordless(this.#setup, ctx, req, options),
      { ignoreWriteErrors: false }
    );
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
    let req: NextRequest | undefined;
    let res: NextResponse | undefined;
    let options: PasswordlessVerifyOptions;
    if (arg1 instanceof NextRequest) {
      // Pages Router / Middleware: verify(req, res, options); the session is written to `res`.
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

    // A write Next refuses (a Server Component) throws, as on nextjs: the code is spent.
    await withCallContext(
      req,
      res,
      (ctx) => verifyPasswordless(this.#setup, ctx, options),
      { ignoreWriteErrors: false }
    );
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
    let req: NextRequest | undefined;
    let options: PasswordlessDbChallengeEmailOptions;
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "challengeWithEmail(req, options): Both arguments required for Pages Router"
        );
      }
      [req, options] = [arg1, arg2];
    } else {
      options = arg1;
    }
    const { ctx } = await readContext(req);
    return challengeDbConnection(this.#setup, ctx, options);
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
    let req: NextRequest | undefined;
    let options: PasswordlessDbChallengePhoneOptions;
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "challengeWithPhoneNumber(req, options): Both arguments required for Pages Router"
        );
      }
      [req, options] = [arg1, arg2];
    } else {
      options = arg1;
    }
    const { ctx } = await readContext(req);
    return challengeDbConnection(this.#setup, ctx, options);
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
    let req: NextRequest | undefined;
    let res: NextResponse | undefined;
    let options: PasswordlessDbGetTokenOptions;
    if (arg1 instanceof NextRequest) {
      // Pages Router / Middleware: loginWithOtp(req, res, options); the session is written to
      // `res`.
      if (!arg2 || !arg3) {
        throw new TypeError(
          "loginWithOtp(req, res, options): All three arguments required for Pages Router"
        );
      }
      [req, res, options] = [arg1, arg2, arg3];
    } else {
      // App Router: loginWithOtp(options); the session is written to `cookies()`.
      options = arg1;
    }

    // A write Next refuses (a Server Component) throws, as on nextjs: the code is spent.
    await withCallContext(
      req,
      res,
      (ctx) => loginWithDbOtp(this.#setup, ctx, options),
      { ignoreWriteErrors: false }
    );
  }
}
