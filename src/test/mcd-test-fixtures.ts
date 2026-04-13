/**
 * Shared test fixtures for MCD (Multiple Custom Domains) tests
 *
 * Provides common constants used across MCD test files to reduce duplication
 * and maintain consistency.
 */

import type { Routes } from "../server/auth-client.js";
import type { TransactionState } from "../server/transaction-store.js";
import type { SessionData } from "../types/index.js";
import type { MCDMetadata } from "../types/mcd.js";

/**
 * Standard Auth0 domain for testing
 */
export const TEST_DOMAIN = "guabu.us.auth0.com";

/**
 * Standard OAuth2 client ID for testing
 */
export const TEST_CLIENT_ID = "my-client-id";

/**
 * Standard OAuth2 client secret for testing
 */
export const TEST_CLIENT_SECRET = "my-client-secret";

/**
 * Standard encryption secret for session/transaction store
 * 32-byte hex string (256 bits)
 */
export const TEST_SECRET =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/**
 * Standard route configuration for testing
 * Matches Auth0 SDK defaults
 */
export const TEST_DEFAULT_ROUTES: Routes = {
  login: "/auth/login",
  logout: "/auth/logout",
  callback: "/auth/callback",
  profile: "/auth/profile",
  accessToken: "/auth/access-token",
  backChannelLogout: "/auth/backchannel-logout",
  connectAccount: "/auth/connect",
  mfaAuthenticators: "/auth/mfa/authenticators",
  mfaChallenge: "/auth/mfa/challenge",
  mfaVerify: "/auth/mfa/verify",
  mfaEnroll: "/auth/mfa/enroll",
  passwordlessStart: "/auth/passwordless/start",
  passwordlessVerify: "/auth/passwordless/verify"
};

/**
 * Creates a TransactionState for testing with default values
 * Used to test transaction storage and callback delegation
 */
export function createTransactionState(
  partial: Partial<TransactionState> = {}
): TransactionState {
  return {
    codeVerifier: "code_verifier_123",
    responseType: "code",
    state: "state_value",
    returnTo: "https://example.com/callback",
    nonce: "nonce_123",
    ...partial
  } as TransactionState;
}

/**
 * Creates MCDMetadata for testing
 * Used to test session domain tracking and validation
 */
export function createMCDMetadata(domain: string, issuer: string): MCDMetadata {
  return { domain, issuer };
}

/**
 * Creates SessionData for testing with default values
 * Used to test session domain gating and backfill
 */
export function createSessionData(
  partial: Partial<SessionData> = {}
): SessionData {
  return {
    user: { sub: "user_123" },
    tokenSet: {
      accessToken: "access_token_123",
      expiresAt: Date.now() + 3600000
    },
    internal: {
      sid: "sid_123",
      createdAt: Date.now()
    },
    ...partial
  };
}
