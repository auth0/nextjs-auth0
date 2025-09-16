import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import auth0Mcp from "./auth0";

const greetToolInputSchema = {
  name: z.string().optional().describe("The name to greet")
} as const;

/**
 * MCP tools with scope-based authorization.
 */
export function registerTools(server: McpServer) {
  server.registerTool(
    "greet",
    {
      title: "Greet Tool",
      description: "A tool that greets a user by name",
      inputSchema: greetToolInputSchema,
      annotations: { readOnlyHint: false }
    },
    auth0Mcp.requireScopes<typeof greetToolInputSchema>(
      ["tool:greet"],
      async (payload, { authInfo }) => {
        const name = payload.name || "World";
        const userId = authInfo.extra.sub;
        return {
          content: [
            {
              type: "text",
              text: `Hello, ${name}! You are authenticated as: ${userId}`
            }
          ]
        };
      }
    )
  );

  server.registerTool(
    "whoami",
    {
      title: "Who Am I Tool",
      description:
        "A tool that returns information about the authenticated user",
      annotations: { readOnlyHint: false }
    },
    auth0Mcp.requireScopes(["tool:whoami"], async (_payload, { authInfo }) => {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { user: authInfo.extra, scopes: authInfo.scopes },
              null,
              2
            )
          }
        ]
      };
    })
  );
}
