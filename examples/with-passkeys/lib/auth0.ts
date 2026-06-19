import { Auth0Client, generateDpopKeyPair } from "@auth0/nextjs-auth0/server";

const dpopKeyPair = process.env.AUTH0_USE_DPOP === "true"
  ? await generateDpopKeyPair()
  : undefined;

export const auth0 = new Auth0Client({
  allowInsecureRequests: true,
  authorizationParameters: {
    scope: "openid profile email offline_access"
  },
  ...(dpopKeyPair && { useDPoP: true, dpopKeyPair })
});
