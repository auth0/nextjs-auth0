/**
 * OAuth 2.0 Authorization Server Metadata endpoint
 */
import { discoverAuthorizationServerMetadata } from "@modelcontextprotocol/sdk/client/auth.js";
import { metadataCorsOptionsRequestHandler } from "mcp-handler";

import { AUTH0_DOMAIN } from "../../../config";

const handler: (req: Request) => Promise<Response> = async () => {
  const oauthMetadata = await discoverAuthorizationServerMetadata(
    new URL(`https://${AUTH0_DOMAIN}`).toString()
  );

  return new Response(JSON.stringify(oauthMetadata));
};

const optionsHandler = metadataCorsOptionsRequestHandler();

// Export the handlers using Nextjs App router naming convention
// GET: Returns the OAuth 2.0 Authorization Server Metadata JSON
// OPTIONS: Handles CORS preflight requests
export { handler as GET, optionsHandler as OPTIONS };
