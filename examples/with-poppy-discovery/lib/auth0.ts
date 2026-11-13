import { Auth0Client } from "@auth0/nextjs-auth0/server";

import poppyConfig from "../auth0-poppy.json";

// Turns on Poppy support: serves the discovery files and recognises agents.
export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig },
  authorizationParameters: {
    // The carts API's identifier. It makes the access token an agent guest
    // gets from the join valid for that API.
    audience: process.env.AUTH0_AUDIENCE
  }
});
