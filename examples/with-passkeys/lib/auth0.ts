import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  allowInsecureRequests: true,
  authorizationParameters: {
    audience: `https://${process.env.AUTH0_DOMAIN}/me/`,
    scope: "openid profile email offline_access create:me:authentication_methods"
  }
});
