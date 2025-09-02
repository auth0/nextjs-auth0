import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

/**
 * Extended authentication information for Auth0-authenticated users.
 *
 * This interface extends the standard MCP AuthInfo with Auth0-specific user identity
 * claims extracted from JWT access tokens. It provides comprehensive user context
 * for MCP tool handlers and middleware.
 *
 **/
export interface Auth extends AuthInfo {
  extra: {
    /** User identifier from Auth0. */
    sub: string;

    /** Standard OAuth 2.0 client_id claim, if available. */
    client_id?: string;

    /** Auth0-specific azp (authorized party) claim, if available. */
    azp?: string;

    /** User's full name, if available. */
    name?: string;

    /** User's email address, if available. */
    email?: string;
  };
}
