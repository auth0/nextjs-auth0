/**
 * OAuth 2.0 Protected Resource Metadata endpoint
 */
import {
  metadataCorsOptionsRequestHandler,
  protectedResourceHandler
} from "mcp-handler";

import { AUTH0_DOMAIN } from "../../../config";

const handler = protectedResourceHandler({
  authServerUrls: [new URL(`https://${AUTH0_DOMAIN}/`).toString()]
});

// Create the OPTIONS handler for CORS preflight requests
// This alllows browsers to make cross-origin requests to this endpoint
const optionsHandler = metadataCorsOptionsRequestHandler();

// Export the handlers using Nextjs App router naming convention
// GET: Returns the protected resource metadata JSON
// OPTIONS: Handles CORS preflight requests
export { handler as GET, optionsHandler as OPTIONS };
