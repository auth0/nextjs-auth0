import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { sqliteSessionStore } from "./db/session-store";

export const auth0Stateful = new Auth0Client({
  sessionStore: sqliteSessionStore,
  session: {
    cookie: {
      // Use a distinct cookie name so the stateless auth0 client (used in layout.tsx)
      // doesn't attempt to decrypt the stateful session ID pointer and crash.
      name: "__session_stateful",
    },
  },
  routes: {
    login: "/auth/stateful/login",
    callback: "/auth/stateful/callback",
    logout: "/auth/stateful/logout",
  },
});
