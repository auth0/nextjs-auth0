import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  authorizationParameters: {
    organization: process.env.AUTH0_ORGANIZATION_ID,
    audience: process.env.AUTH0_AUDIENCE,
    scope: "openid profile email offline_access read:my_org:configuration read:my_org:members read:my_org:member_roles create:my_org:member_invitations create:my_org:member_roles delete:my_org:member_roles"
  }
});
