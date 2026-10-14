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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
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
    throw new Error("not implemented");
  }
}
