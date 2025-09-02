import { ApiClient, VerifyAccessTokenError } from "@auth0/auth0-api-js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ZodRawShape } from "zod";

import { AUTH0_AUDIENCE, AUTH0_DOMAIN } from "./config";
import { Auth } from "./types";

interface Auth0McpInstance {
  verifyToken: ReturnType<typeof createTokenVerifier>;
  requireScopes: ReturnType<typeof createScopeValidator>;
}

const auth0Mcp = createAuth0Mcp();
export default auth0Mcp;

export function createAuth0Mcp(): Auth0McpInstance {
  const verifyToken = createTokenVerifier();
  const requireScopes = createScopeValidator();
  return {
    verifyToken,
    requireScopes
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Creates a JWT token verifier for Auth0-issued access tokens.
 *
 * This function returns a reusable `verify` function that validates JWT signatures,
 * token claims, and extracts user identity information for MCP integration using
 * the official @auth0/auth0-api-js library.
 */
function createTokenVerifier() {
  const apiClient = new ApiClient({
    domain: AUTH0_DOMAIN,
    audience: AUTH0_AUDIENCE
  });

  return async function verify(token: string): Promise<Auth> {
    try {
      const decoded = await apiClient.verifyAccessToken({
        accessToken: token
      });

      if (!isNonEmptyString(decoded.sub)) {
        throw new InvalidTokenError("Token is missing 'sub' claim");
      }

      let clientId: string | null = null;
      if (isNonEmptyString(decoded.client_id)) {
        clientId = decoded.client_id;
      } else if (isNonEmptyString(decoded.azp)) {
        clientId = decoded.azp;
      }

      if (!clientId) {
        throw new InvalidTokenError(
          "Token is missing 'client_id' or 'azp' claim"
        );
      }

      return {
        token,
        clientId,
        scopes:
          typeof decoded.scope === "string"
            ? decoded.scope.split(" ").filter(Boolean)
            : [],
        ...(decoded.exp && { expiresAt: decoded.exp }),
        extra: {
          sub: decoded.sub,
          ...(isNonEmptyString(decoded.client_id) && {
            client_id: decoded.client_id
          }),
          ...(isNonEmptyString(decoded.azp) && { azp: decoded.azp }),
          ...(isNonEmptyString(decoded.name) && { name: decoded.name }),
          ...(isNonEmptyString(decoded.email) && { email: decoded.email })
        }
      };
    } catch (error) {
      if (error instanceof VerifyAccessTokenError) {
        throw new InvalidTokenError(error.message);
      }
      throw error;
    }
  };
}

/**
 * Wraps an MCP tool handler to enforce required OAuth scopes.
 *
 * This is a higher-order function that adds scope-based authorization to MCP tools.
 * It validates that the authenticated user's JWT token contains all required scopes
 * before allowing access to the wrapped tool.
 */
function createScopeValidator() {
  /**
   * Wraps a tool handler with scope validation.
   * This function ensures that the tool can only be executed if the user has the required OAuth scopes.
   */
  return function requireScopes<T extends ZodRawShape>(
    requiredScopes: readonly string[],
    handler: (args: T, extra: { authInfo: Auth }) => Promise<CallToolResult>
  ): ToolCallback<T> {
    return (async (args, extra) => {
      // To support both context-only and payload+context handlers
      let context = extra;

      if (!extra) {
        context = args as Parameters<ToolCallback<T>>[1];
      }

      if (!context?.authInfo) {
        throw new Error("Authentication info is required to execute this tool");
      }

      const userScopes = context.authInfo.scopes;
      const hasScopes = requiredScopes.every((scope) =>
        userScopes.includes(scope)
      );
      if (!hasScopes) {
        throw new Error(
          `Missing required scopes: ${requiredScopes.join(", ")}`
        );
      }

      return handler(args as T, { authInfo: context.authInfo as Auth });
    }) as ToolCallback<T>;
  };
}
