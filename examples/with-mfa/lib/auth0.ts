import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Step-up MFA: the audience is not set here, so logging in does not need MFA. Asking for a token
// for the protected API (getAccessToken({ audience })) is what triggers it.
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email offline_access",
  },
});
