"use server";

import { auth0 } from "@/lib/auth0";
import type {
  PasskeyChallengeResponse,
  PasskeySignupChallengeOptions,
  PasskeyVerifyOptions
} from "@auth0/nextjs-auth0/types";

/**
 * Step 1 — run any server-side validation, then fetch the signup challenge.
 *
 * This is where you inject logic before the WebAuthn ceremony:
 * check if the email already exists, enforce invite-only signups,
 * validate org membership, rate-limit, etc.
 */
export async function getSignupChallenge(
  options: PasskeySignupChallengeOptions
): Promise<PasskeyChallengeResponse> {
  if (!options.email) {
    throw { error: "invalid_request", error_description: "Email is required." };
  }

  // Add your own pre-challenge logic here, e.g.:
  // const exists = await db.users.findByEmail(options.email);
  // if (exists) throw { error: "email_taken", error_description: "Account already exists." };

  return auth0.passkey.signupChallenge(options);
}

/**
 * Step 1 — fetch the login challenge.
 * Add any pre-challenge checks here before the browser ceremony runs.
 */
export async function getLoginChallenge(): Promise<PasskeyChallengeResponse> {
  return auth0.passkey.loginChallenge();
}

/**
 * Step 3 — verify the signed WebAuthn credential and create the session.
 * Session cookie is set automatically via next/headers.
 *
 * Add post-verification logic here, e.g. write user to your DB on first
 * signup, emit analytics events, assign roles.
 */
export async function verifyPasskey(options: PasskeyVerifyOptions): Promise<void> {
  await auth0.passkey.verify(options);
}
