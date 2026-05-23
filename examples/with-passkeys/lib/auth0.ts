import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  allowInsecureRequests: true,
  authorizationParameters: {
    audience: "https://mtls-test.local.dev.auth0.com/me/",
    scope: "openid profile email offline_access create:me:authentication_methods"
  }
});
