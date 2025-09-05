import "dotenv/config";

export const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN ?? "your-tenant.auth0.com";
export const AUTH0_AUDIENCE =
  process.env.AUTH0_AUDIENCE ?? "http://localhost:3000";

/**
 * CORS headers to allow cross-origin requests to this endpoint
 * Configure appropriately for production
 */
export const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // Adjust as needed for production
  "Access-Control-Allow-Methods": "GET, OPTIONS"
};
