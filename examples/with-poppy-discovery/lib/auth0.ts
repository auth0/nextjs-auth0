import { Auth0Client } from "@auth0/nextjs-auth0/server";

import poppyConfig from "../auth0-poppy.json";

// Turns on Poppy support: serves the discovery files and recognises agents.
export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig }
});
