import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  // Mounts the /auth/connect route. The connectAccount() method works without it.
  enableConnectAccountEndpoint: true,
  authorizationParameters: {
    // A refresh token is needed for the My Account API and for Token Vault.
    scope: "openid profile email offline_access",
  },
});
