import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  authorizationParameters: {
    // Set an API audience to get a JWT access token.
    // Without this, Auth0 returns an opaque token for /userinfo only.
    audience: process.env.AUTH0_AUDIENCE
  }
});
