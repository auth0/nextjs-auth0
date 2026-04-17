import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll } from "vitest";

import type { Routes } from "../server/auth-client.js";

export function getDefaultRoutes(): Routes {
  return {
    login: process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login",
    logout: "/auth/logout",
    callback: "/auth/callback",
    backChannelLogout: "/auth/backchannel-logout",
    profile: process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
    accessToken:
      process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
    connectAccount: "/auth/connect",
    mfaAuthenticators:
      process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE ||
      "/auth/mfa/authenticators",
    mfaChallenge:
      process.env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE || "/auth/mfa/challenge",
    mfaVerify: process.env.NEXT_PUBLIC_MFA_VERIFY_ROUTE || "/auth/mfa/verify",
    mfaAssociate:
      process.env.NEXT_PUBLIC_MFA_ASSOCIATE_ROUTE || "/auth/mfa/associate"
  };
}

/**
 * Shared test configuration with the intersection of commonly used fields
 * across multiple test files.
 */
export const DEFAULT_TEST_CONFIG = {
  domain: "test.auth0.local",
  clientId: "test_client_id",
  clientSecret: "test_client_secret",
  appBaseUrl: "https://example.com",
  sub: "user_test_123",
  sid: "session_test_123",
  alg: "RS256" as const
};

/**
 * Factory function to create authorization server metadata.
 * Returns common OpenID Connect discovery metadata fields with optional overrides.
 *
 * @param domain - The authorization server domain
 * @param overrides - Optional fields to override defaults
 * @returns Authorization server metadata object
 */
export function createAuthorizationServerMetadata(
  domain: string,
  overrides?: Record<string, unknown>
) {
  return {
    issuer: `https://${domain}`,
    authorization_endpoint: `https://${domain}/authorize`,
    token_endpoint: `https://${domain}/oauth/token`,
    jwks_uri: `https://${domain}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    dpop_signing_alg_values_supported: ["RS256", "ES256"],
    ...overrides
  };
}

/**
 * Sets up the standard MSW (Mock Service Worker) lifecycle hooks.
 * Wires up beforeAll/afterEach/afterAll handlers for test server.
 *
 * @param server - The MSW test server instance from setupServer()
 */
export function setupMswLifecycle(server: ReturnType<typeof setupServer>) {
  beforeAll(() => {
    server.listen({ onUnhandledRequest: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });
}
