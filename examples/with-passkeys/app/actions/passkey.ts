"use server";

import { auth0 } from "@/lib/auth0";
import {
  PasskeyChallengeError,
  PasskeyGetTokenError,
  PasskeyRegisterError
} from "@auth0/nextjs-auth0/errors";
import { MfaRequiredError } from "@auth0/nextjs-auth0/server";
import type {
  PasskeyAuthResponse,
  PasskeyChallengeResponse,
  PasskeyRegisterOptions,
  PasskeyRegisterResponse,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier
} from "@auth0/nextjs-auth0/types";

// Every action returns a plain object: properties on errors thrown from a
// Server Action do not reach the browser.
type ActionError = { ok: false; error: string; error_description: string };

/**
 * Step 1 — run any server-side validation, then fetch the signup challenge.
 *
 * This is where you inject logic before the WebAuthn ceremony:
 * check if the email already exists, enforce invite-only signups,
 * validate org membership, rate-limit, etc.
 *
 * `challenge.verificationRequired` lists the identifiers ("email", "phone")
 * the user must verify with a one-time code before creating the passkey.
 * Every call sends new codes, so rate-limit it in production.
 */
export async function getSignupChallenge(
  options: Pick<PasskeyRegisterOptions, "email" | "name" | "phoneNumber">
): Promise<{ ok: true; challenge: PasskeyRegisterResponse } | ActionError> {
  // A Server Action is a public endpoint: take only the fields this form
  // collects, never the whole object. Spreading client input would let a caller
  // set `connection`, `organization`, `userMetadata` and the like.
  const { email, name, phoneNumber } = options ?? {};
  if (typeof email !== "string" || !email) {
    return { ok: false, error: "invalid_request", error_description: "Email is required." };
  }

  // Add your own pre-challenge logic here, e.g.:
  // const exists = await db.users.findByEmail(email);
  // if (exists) return { ok: false, error: "email_taken", error_description: "Account already exists." };

  try {
    const challenge = await auth0.passkey.register({
      email,
      ...(typeof name === "string" && name && { name }),
      // deliveryMethod is the channel for the phone code, "text" or "voice".
      ...(typeof phoneNumber === "string" &&
        phoneNumber && { phoneNumber, deliveryMethod: "text" as const })
    });
    return { ok: true, challenge };
  } catch (err) {
    if (err instanceof PasskeyRegisterError) {
      return { ok: false, error: err.error, error_description: err.error_description };
    }
    throw err;
  }
}

/**
 * Step 1 — fetch the login challenge.
 * Add any pre-challenge checks here before the browser ceremony runs.
 */
export async function getLoginChallenge(): Promise<
  { ok: true; challenge: PasskeyChallengeResponse } | ActionError
> {
  try {
    return { ok: true, challenge: await auth0.passkey.challenge() };
  } catch (err) {
    if (err instanceof PasskeyChallengeError) {
      return { ok: false, error: err.error, error_description: err.error_description };
    }
    throw err;
  }
}

export type VerifyPasskeyResult =
  | { ok: true }
  | { ok: false; error: "mfa_required"; mfaToken: string }
  | (ActionError & {
      // A verification code was wrong and the session is still alive.
      retryable: boolean;
      // Retry with this session. Auth0 echoes the original today.
      authSession?: string;
      // Identifiers whose codes still need to be entered.
      verificationRequired?: PasskeyVerificationIdentifier[];
    });

/**
 * Step 3 — verify the signed WebAuthn credential and create the session.
 * Session cookie is set automatically via next/headers.
 *
 * `verification` carries the one-time codes for a signup that requires
 * identifier verification, keyed "email" / "phone".
 *
 * Add post-verification logic here, e.g. write user to your DB on first
 * signup, emit analytics events, assign roles.
 */
export async function verifyPasskey(
  authSession: string,
  authResponse: PasskeyAuthResponse,
  verification?: PasskeyVerificationCodes
): Promise<VerifyPasskeyResult> {
  try {
    await auth0.passkey.getToken({ authSession, authResponse, verification });
    return { ok: true };
  } catch (err) {
    if (err instanceof MfaRequiredError) {
      // The passkey (and any codes) were accepted and the user must complete
      // MFA. err.mfa_token is encrypted by the SDK, so it is safe to return.
      // The browser continues with the client `mfa` helper, which creates the
      // session when MFA succeeds.
      return { ok: false, error: "mfa_required", mfaToken: err.mfa_token };
    }
    if (err instanceof PasskeyGetTokenError) {
      return {
        ok: false,
        error: err.error,
        error_description: err.error_description,
        retryable: err.isRetryable,
        authSession: err.authSession,
        verificationRequired: err.verificationRequired
      };
    }
    throw err;
  }
}
