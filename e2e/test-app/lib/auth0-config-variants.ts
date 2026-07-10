import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Each export is a named Auth0Client instance with exactly one option overridden
// from the default. Used by variant API routes to test constructor option behavior.

export const auth0LogoutStrategyV2 = new Auth0Client({
  logoutStrategy: "v2",
});

export const auth0NoIdTokenHint = new Auth0Client({
  includeIdTokenHintInOIDCLogoutUrl: false,
});

export const auth0NoContentProfile = new Auth0Client({
  noContentProfileResponseWhenUnauthenticated: true,
});

export const auth0SignInReturnTo = new Auth0Client({
  signInReturnToPath: "/dashboard",
});

export const auth0AccessTokenEndpointDisabled = new Auth0Client({
  enableAccessTokenEndpoint: false,
});

export const auth0CustomCookieName = new Auth0Client({
  session: {
    cookie: { name: "__custom_session" },
  },
});

export const auth0CustomTxnPrefix = new Auth0Client({
  transactionCookie: { prefix: "__t_" },
});

export const auth0BeforeSessionSaved = new Auth0Client({
  beforeSessionSaved: async (session) => ({
    ...session,
    user: { ...session.user, injectedClaim: "from-hook" },
  }),
});

export const auth0OnCallback = new Auth0Client({
  onCallback: async (_err, ctx) => {
    const { NextResponse } = await import("next/server.js");
    return NextResponse.redirect(new URL("/hook-redirect", ctx.appBaseUrl));
  },
});

export const auth0WithPAR = new Auth0Client({
  pushedAuthorizationRequests: true,
});

export const auth0WithAuthzParams = new Auth0Client({
  authorizationParameters: {
    ui_locales: "fr",
    acr_values: "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
  },
});

export const auth0ShortAbsoluteDuration = new Auth0Client({
  session: {
    absoluteDuration: 1, // 1 second — sessions expire immediately for test assertions
    rolling: false,
  },
});
