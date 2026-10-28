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
import { withCallContext } from "../engine/call-context.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import {
  challengePasskey,
  enrollmentChallenge,
  enrollmentVerify,
  getPasskeyToken,
  registerPasskey
} from "./passkey-operations.js";

/**
 * Server-side passkey authentication API.
 * The engine sends the signup, login and token requests and saves the session; enrollment is
 * nextjs's MyAccount code.
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
  #setup: EngineSetup;

  /**
   * @internal Reached through `Auth0Client.passkey`.
   */
  constructor(setup: EngineSetup) {
    this.#setup = setup;
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
    const [req, options] =
      arg1 instanceof NextRequest ? [arg1, arg2] : [undefined, arg1];
    const { ctx } = await readContext(req);
    return registerPasskey(this.#setup, ctx, options);
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
    const [req, options] =
      arg1 instanceof NextRequest ? [arg1, arg2] : [undefined, arg1];
    const { ctx } = await readContext(req);
    return challengePasskey(this.#setup, ctx, options);
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
    let req: NextRequest | undefined;
    let res: NextResponse | undefined;
    let options: PasskeyGetTokenOptions;
    if (arg1 instanceof NextRequest) {
      // Middleware: getToken(req, res, options); the session is written to `res`.
      if (!arg2 || !arg3) {
        throw new TypeError(
          "getToken(req, res, options): All three arguments required for Pages Router"
        );
      }
      [req, res, options] = [arg1, arg2, arg3];
    } else {
      // App Router: getToken(options); the session is written to `cookies()`.
      if (arg2 !== undefined || arg3 !== undefined) {
        throw new TypeError(
          "getToken(options): Only one argument allowed for App Router"
        );
      }
      options = arg1;
    }

    // A write Next refuses (a Server Component) throws, as on nextjs: the credential is spent.
    await withCallContext(
      req,
      res,
      (ctx) => getPasskeyToken(this.#setup, ctx, options),
      { ignoreWriteErrors: false }
    );
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
    const [req, options] =
      arg1 instanceof NextRequest ? [arg1, arg2] : [undefined, arg1];
    // A refreshed MyAccount token is saved where the call form allows.
    return withCallContext(req, undefined, (ctx) =>
      enrollmentChallenge(this.#setup, ctx, options)
    );
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
    let req: NextRequest | undefined;
    let options: PasskeyEnrollmentVerifyOptions;
    if (arg1 instanceof NextRequest) {
      if (!arg2) {
        throw new TypeError(
          "enrollmentVerify(req, options): Both arguments required for Pages Router"
        );
      }
      [req, options] = [arg1, arg2];
    } else {
      options = arg1;
    }
    // A refreshed MyAccount token is saved where the call form allows.
    return withCallContext(req, undefined, (ctx) =>
      enrollmentVerify(this.#setup, ctx, options)
    );
  }
}
