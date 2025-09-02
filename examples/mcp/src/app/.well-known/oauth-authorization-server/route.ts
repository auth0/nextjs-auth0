/**
 * OAuth 2.0 Authorization Server Metadata endpoint
 *
 * This endpoint ensures backwards compatibility with OAuth clients that expect
 * authorization server metadata at /.well-known/oauth-authorization-server
 */
import { discoverAuthorizationServerMetadata } from "@modelcontextprotocol/sdk/client/auth.js";

import { AUTH0_DOMAIN, corsHeaders } from "../../../config";

const handler: (req: Request) => Promise<Response> = async () => {
  const oauthMetadata = await discoverAuthorizationServerMetadata(
    new URL(`https://${AUTH0_DOMAIN}`).toString()
  );

  return new Response(JSON.stringify(oauthMetadata), { headers: corsHeaders });
};

// Create the OPTIONS handler for CORS preflight requests
// This allows browsers to make cross-origin requests to this endpoint
const optionsHandler = () => {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
};

// Export the handlers using Nextjs App router naming convention
// GET: Returns the OAuth 2.0 Authorization Server Metadata JSON
// OPTIONS: Handles CORS preflight requests
export { handler as GET, optionsHandler as OPTIONS };
