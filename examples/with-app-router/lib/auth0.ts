import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  // This is the key setting that enables API route mode
  routes: {
    login: "/api/auth/login",
    logout: "/api/auth/logout",
    callback: "/api/auth/callback"
  }
});
