import {
  PasswordlessStartError,
  PasswordlessVerifyError
} from "../../errors/index.js";
import type {
  PasswordlessClient,
  PasswordlessStartOptions,
  PasswordlessVerifyOptions
} from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Client-side passwordless authentication API (singleton).
 *
 * Thin fetch() wrappers that call the SDK's server-side route handlers.
 * All business logic (OTP delivery, token exchange, session creation) runs server-side.
 *
 * @example Email OTP
 * ```typescript
 * 'use client';
 * import { passwordless } from '@auth0/nextjs-auth0/client';
 *
 * // 1. Send OTP
 * await passwordless.start({ connection: 'email', email: 'user@example.com', send: 'code' });
 *
 * // 2. Verify OTP — creates session automatically
 * await passwordless.verify({ connection: 'email', email: 'user@example.com', verificationCode: '123456' });
 * window.location.href = '/dashboard';
 * ```
 *
 * @example SMS OTP
 * ```typescript
 * 'use client';
 * import { passwordless } from '@auth0/nextjs-auth0/client';
 *
 * await passwordless.start({ connection: 'sms', phoneNumber: '+14155550100' });
 * await passwordless.verify({ connection: 'sms', phoneNumber: '+14155550100', verificationCode: '123456' });
 * ```
 */
class ClientPasswordlessClient implements PasswordlessClient {
  /**
   * Initiate a passwordless flow by sending an OTP to the user's email or phone.
   *
   * @param options - Email or SMS start options
   * @throws {PasswordlessStartError} On Auth0 API failure or network error
   */
  async start(options: PasswordlessStartOptions): Promise<void> {
    const url = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE ||
        "/auth/passwordless/start"
    );

    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "omit",
        body: JSON.stringify(options)
      });
    } catch (e) {
      throw new PasswordlessStartError(
        "client_error",
        e instanceof Error ? e.message : "Network error",
        undefined
      );
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        error: "client_error",
        error_description: "Failed to parse error response"
      }));
      throw new PasswordlessStartError(
        error.error ?? "client_error",
        error.error_description ?? "Passwordless start failed",
        undefined
      );
    }
  }

  /**
   * Verify a passwordless OTP. On success the server creates a session
   * and sets the session cookie — the browser picks it up automatically.
   *
   * @param options - Email or SMS verify options including the OTP
   * @throws {PasswordlessVerifyError} On wrong code, expired code, or network error
   */
  async verify(options: PasswordlessVerifyOptions): Promise<void> {
    const url = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE ||
        "/auth/passwordless/verify"
    );

    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // Session cookie must be received
        body: JSON.stringify(options)
      });
    } catch (e) {
      throw new PasswordlessVerifyError(
        "client_error",
        e instanceof Error ? e.message : "Network error",
        undefined
      );
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        error: "client_error",
        error_description: "Failed to parse error response"
      }));
      throw new PasswordlessVerifyError(
        error.error ?? "client_error",
        error.error_description ?? "Passwordless verify failed",
        undefined
      );
    }
  }
}

/**
 * Client-side passwordless authentication singleton.
 *
 * @example
 * ```typescript
 * import { passwordless } from '@auth0/nextjs-auth0/client';
 *
 * await passwordless.start({ connection: 'email', email: 'user@example.com', send: 'code' });
 * await passwordless.verify({ connection: 'email', email: 'user@example.com', verificationCode: '123456' });
 * ```
 */
export const passwordless: PasswordlessClient = new ClientPasswordlessClient();
