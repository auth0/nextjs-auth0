import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Initialize the Auth0 client 
export const auth0 = new Auth0Client({
  // Options are loaded from environment variables by default
  authorizationParameters: {
    // Request the protected API audience during login.
    // The MFA Action will trigger when this audience is requested.
    scope: process.env.AUTH0_SCOPE || "openid profile email offline_access",
    audience: process.env.AUTH0_AUDIENCE,
  }
});
