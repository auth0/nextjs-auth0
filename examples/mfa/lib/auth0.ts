import { Auth0Client } from "@auth0/nextjs-auth0/server";

/**
 * SDK initialization WITHOUT audience in authorizationParameters.
 *
 * For step-up MFA: request audience via getAccessToken() at the point
 * where elevated permissions are needed, not during initial login.
 */
export const auth0 = new Auth0Client();
