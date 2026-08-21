/**
 * Anonymous Session Types for @auth0/nextjs-auth0
 * Public API types and configuration contracts for anonymous sessions
 */

import type * as jose from "jose";

/**
 * Session object returned to SDK consumers (access token exposed, session token stays server-side)
 */
export interface AnonymousSession {
  /** Anonymous subject, always "anon@{uuid}" (extracted from access token sub claim) */
  id: string;
  /** Bearer token for API calls; validates per access_token JWT expiry */
  accessToken: string;
  /** Unix seconds at which accessToken expires */
  expiresAt: number;
  /** User-set top-level key-value metadata, max 1KB serialized, optional */
  metadata?: Record<string, unknown>;
}

/**
 * Metadata payload shape for client updates
 */
export type AnonymousSessionMetadata = Record<string, unknown>;

/**
 * Config block for auth0.ts setup
 */
export interface AnonymousSessionConfig {
  /** Master switch. Defaults to false: routes not mounted, methods no-op */
  enabled: boolean;
  /**
   * Audience requested for the anonymous access token. When omitted the
   * authorization server applies the tenant default. The resource server must
   * allow anonymous access, otherwise the server reports `invalid_target`.
   */
  audience?: string;
  /**
   * Space-separated scopes requested for the anonymous access token. When
   * omitted the authorization server applies the tenant default. Scopes that
   * are not granted to anonymous subjects are reported as `invalid_scope`.
   */
  scope?: string;
  cookie?: {
    /** Cookie name. Defaults to "auth0_anon" */
    name?: string;
    /** SameSite attribute. Defaults to "lax" */
    sameSite?: "lax" | "strict" | "none";
    /** Secure flag. Defaults to true */
    secure?: boolean;
    /** Cookie max age in seconds. Defaults to 2592000 (30 days). */
    maxAge?: number;
  };
}

/**
 * Hook options shape
 */
export type UseAnonymousSessionOptions = { route?: string };

/**
 * Internal cookie payload (stays encrypted in cookie; never surfaces to SDK consumer)
 */
export interface AnonymousCookiePayload extends jose.JWTPayload {
  session_token: string; // opaque, non-API handle for renewal/metadata
  access_token: string; // standard bearer token
  expires_at: number; // Unix seconds, access token expiry
  metadata?: Record<string, unknown>; // last persisted metadata
}

/**
 * Server-side token response from POST /anonymous/token
 * CASCADE-v2 M5: Authorization server wire response includes session_expires_in (30d),
 * but SDK deliberately ignores it; renewal is error-driven/reactive only (no expiry check).
 */
export interface AnonymousTokenResponse {
  token_type: "Bearer";
  session_token?: string; // present only on create (HTTP 201); omitted on renew (HTTP 200)
  access_token: string;
  expires_in: number;
  scope?: string; // optional: AS may omit if no scope requested or default scope applied
  metadata?: Record<string, unknown>; // merged metadata returned by Auth0
  session_expires_in?: number; // present on wire (30d); intentionally unused by SDK
}

/**
 * Helper: check if error is recoverable (silent recovery path)
 */
export function isRecoverableAnonymousError(err: unknown): boolean {
  // Check if error is AnonymousSessionError with code session_expired or invalid_session_token
  if (
    err &&
    typeof err === "object" &&
    "code" in err &&
    typeof (err as { code: unknown }).code === "string"
  ) {
    const code = (err as { code: string }).code;
    return code === "session_expired" || code === "invalid_session_token";
  }
  return false;
}
