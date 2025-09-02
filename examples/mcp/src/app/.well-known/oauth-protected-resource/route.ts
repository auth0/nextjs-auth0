/**
 * OAuth 2.0 Protected Resource Metadata endpoint
 */
import { generateProtectedResourceMetadata } from "mcp-handler";

import { AUTH0_AUDIENCE, AUTH0_DOMAIN, corsHeaders } from "../../../config";

const handler = () => {
  const metadata = generateProtectedResourceMetadata({
    authServerUrls: [new URL(`https://${AUTH0_DOMAIN}/`).toString()],
    resourceUrl: AUTH0_AUDIENCE,
    additionalMetadata: {
      scopes_supported: ["tool:whoami", "tool:greet"],
      jwks_uri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
    }
  });

  return new Response(JSON.stringify(metadata), {
    headers: corsHeaders
  });
};

// Create the OPTIONS handler for CORS preflight requests
// This alllows browsers to make cross-origin requests to this endpoint
const optionsHandler = () => {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
};

// Export the handlers using Nextjs App router naming convention
// GET: Returns the protected resource metadata JSON
// OPTIONS: Handles CORS preflight requests
export { handler as GET, optionsHandler as OPTIONS };
