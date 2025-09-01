import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler, withMcpAuth } from "mcp-handler";

import auth0Mcp from "../../auth0";
import { registerTools } from "../../tools";

const initializeServer = async (server: McpServer) => {
  registerTools(server);
};

const handler = createMcpHandler(
  initializeServer,
  {
    // MCP Server configuration options
    serverInfo: {
      name: "Example Nextjs MCP Server",
      version: "1.0.0"
    }
  },
  {
    // Handler configuration options
    verboseLogs: true
  }
);

// Wrap the mcp handler with Auth0 authentication middleware
// This ensures all requests are authenticated before reaching the MCP handler
const authHandler = withMcpAuth(
  handler,
  async (_req, token) => {
    if (!token) {
      return;
    }
    return auth0Mcp.verifyToken(token);
  },
  {
    required: true
  }
);

export { authHandler as GET, authHandler as POST };
