/**
 * Test Helpers for Proxy Handler Tests
 *
 * Shared utilities for testing AuthClient proxy functionality with MSW mocking.
 * These helpers support Bearer/DPoP authentication, session management, and
 * DPoP nonce retry validation.
 */

import { encrypt } from "../server/cookies.js";
import { SessionData } from "../types/index.js";

/**
 * Create initial session data for testing
 *
 * @param overrides - Partial session data to override defaults
 * @returns Complete SessionData object
 */
export function createInitialSessionData(
  overrides: Partial<SessionData> = {}
): SessionData {
  const now = Math.floor(Date.now() / 1000);

  const defaults: SessionData = {
    tokenSet: {
      accessToken: "at_test_123",
      refreshToken: "rt_test_123",
      expiresAt: now + 3600, // 1 hour from now
      scope: "read:data write:data",
      token_type: "Bearer",
      // Add audience to match the /me proxy route configuration
      // This ensures the token is recognized as valid for the proxy route
      // Without this, getTokenSet will think it needs a new token for the requested audience
      audience: "https://test.auth0.local/me/"
    },
    user: {
      sub: "user_test_123"
    },
    internal: {
      sid: "session_test_123",
      createdAt: now
    }
  };

  // Deep merge tokenSet if provided in overrides
  if (overrides.tokenSet) {
    return {
      ...defaults,
      ...overrides,
      tokenSet: {
        ...defaults.tokenSet,
        ...overrides.tokenSet
      }
    };
  }

  return {
    ...defaults,
    ...overrides
  };
}

/**
 * Create session cookie from session data
 *
 * @param sessionData - Session data to encrypt
 * @param secretKey - Secret key for encryption
 * @returns Cookie string in format "__session={encryptedValue}"
 */
export async function createSessionCookie(
  sessionData: SessionData,
  secretKey: string
): Promise<string> {
  const maxAge = 60 * 60; // 1 hour
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  const encryptedValue = await encrypt(sessionData, secretKey, expiration);
  return `__session=${encryptedValue}`;
}

/**
 * Extract DPoP nonce and claims from DPoP JWT header
 *
 * @param dpopHeader - DPoP JWT header value
 * @returns Object with nonce presence, nonce value, and JWT claims
 */
export function extractDPoPInfo(dpopHeader: string | null): {
  hasNonce: boolean;
  nonce?: string;
  htm?: string;
  htu?: string;
  jti?: string;
  iat?: number;
} {
  if (!dpopHeader || typeof dpopHeader !== "string") {
    return { hasNonce: false };
  }

  try {
    const parts = dpopHeader.split(".");
    if (parts.length === 3 && parts[1]) {
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString("utf-8")
      );
      return {
        hasNonce: "nonce" in payload,
        nonce: payload.nonce,
        htm: payload.htm,
        htu: payload.htu,
        jti: payload.jti,
        iat: payload.iat
      };
    }
  } catch {
    // If parsing fails, return no nonce
  }

  return { hasNonce: false };
}

/**
 * Create stateful DPoP nonce retry handler for upstream API
 *
 * This handler tracks request attempts and simulates the DPoP nonce retry flow:
 * - First request: Returns 401 with WWW-Authenticate header containing use_dpop_nonce error and DPoP-Nonce header
 * - Second request: Returns success response
 *
 * Per RFC 9449 Section 8: Resource servers signal DPoP nonce requirement via 401 with WWW-Authenticate header
 *
 * @param config - Configuration for the handler
 * @returns Handler function and state object for assertions
 */
export function createDPoPNonceRetryHandler(config: {
  baseUrl: string;
  path: string;
  method: string;
  successResponse?: any;
  successStatus?: number;
}) {
  const state = {
    requestCount: 0,
    requests: [] as Array<{
      attempt: number;
      hasDPoP: boolean;
      hasNonce: boolean;
      nonce?: string;
      dpopJwt?: string;
    }>
  };

  const handler = async ({ request }: { request: Request }) => {
    state.requestCount++;

    const dpopHeader = request.headers.get("dpop");
    const dpopInfo = extractDPoPInfo(dpopHeader);

    state.requests.push({
      attempt: state.requestCount,
      hasDPoP: !!dpopHeader,
      hasNonce: dpopInfo.hasNonce,
      nonce: dpopInfo.nonce,
      dpopJwt: dpopHeader || undefined
    });

    // First request: return use_dpop_nonce error
    // RFC 9449 Section 8: Resource server responds with 401 and WWW-Authenticate header
    if (state.requestCount === 1) {
      return new Response(
        JSON.stringify({
          error: "use_dpop_nonce",
          error_description: "DPoP nonce is required"
        }),
        {
          status: 401,
          headers: {
            "www-authenticate": 'DPoP error="use_dpop_nonce"',
            "dpop-nonce": "server_nonce_123",
            "content-type": "application/json"
          }
        }
      );
    }

    // Second request: return success
    return Response.json(config.successResponse || { success: true }, {
      status: config.successStatus || 200
    });
  };

  return { handler, state };
}
