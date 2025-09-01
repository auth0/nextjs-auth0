import { ApiClient, VerifyAccessTokenError } from "@auth0/auth0-api-js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ZodRawShape } from "zod";

import { AUTH0_AUDIENCE, AUTH0_DOMAIN } from "./config";
import { Auth } from "./types";

const auth0Mcp = createAuth0Mcp();
export default auth0Mcp;

export function createAuth0Mcp() {
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

function createScopeValidator() {
  return function requireScopes<T extends ZodRawShape>(
    requiredScopes: string[],
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
