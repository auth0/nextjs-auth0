---
name: mfa
description: >-
  Multi-factor authentication with @auth0/nextjs-auth0 v4: redirect step-up via
  Universal Login (amr gating), server-side step-up on mfa_required, the MFA
  management API (getAuthenticators, enroll, challenge, verify), and reactive
  step-up via mfa.challengeWithPopup(). Covers the beforeSessionSaved amr hook,
  the secure mfa_token handoff, and MFA error classes.
metadata:
  type: sub-skill
  library: nextjs-auth0
  library_version: 4.30.0
requires:
  - nextjs-auth0
---

# @auth0/nextjs-auth0 — MFA (v4)

**Minimum version:** 4.15.0 for base MFA + the MFA management APIs; reactive popup step-up (`mfa.challengeWithPopup`) requires 4.19.0+.

Framework-specific surface only. The shared mechanic, tenant config, `amr`/error tables, and full MFA API detail live in `guides/mfa.md` at the package root.

Singleton client (`lib/auth0.ts`):

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";
export const auth0 = new Auth0Client({ mfaTokenTtl: 300 }); // seconds; matches Auth0's mfa_token expiry. Or AUTH0_MFA_TOKEN_TTL env var.
```

MFA methods are on `auth0.mfa` (server, `@auth0/nextjs-auth0/server`) and the `mfa` named export (client, `@auth0/nextjs-auth0/client`). Errors import from `@auth0/nextjs-auth0/errors`.

## Flow 0 — redirect step-up via Universal Login (use this when the task says "redirect them to step up")

Gate the action on the `amr` claim; when MFA is missing, redirect through v4's login route with the PAPE `acr_values` + `max_age=0`. v4 has **no `handleLogin` export** — login is middleware-driven, so pass the params one of two ways (both verified on 4.30.0). Do not grep node_modules to rediscover this.

Step 1 — persist `amr` so the gate can read it. Add the `beforeSessionSaved` hook (see "Reading `amr`" below); without it `session.user.amr` is always undefined and the redirect loops.

Step 2 — trigger the step-up. Either:

**(a) Redirect to `/auth/login` with query params (simplest).** `handleLogin` forwards every query param except `challengeMode`/`returnTo` straight to `/authorize`:

```ts
import { redirect } from "next/navigation";

const MFA_ACR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
redirect(`/auth/login?acr_values=${encodeURIComponent(MFA_ACR)}&max_age=0&returnTo=/dashboard/transfer`);
```

**(b) Custom Route Handler calling `auth0.startInteractiveLogin` (type-safe).** Signature: `startInteractiveLogin(options?: StartInteractiveLoginOptions): Promise<NextResponse>`:

```ts
// app/auth/step-up/route.ts
import type { NextResponse } from "next/server";
import type { StartInteractiveLoginOptions } from "@auth0/nextjs-auth0/types";
import { auth0 } from "@/lib/auth0";

export async function GET(): Promise<NextResponse> {
  const options: StartInteractiveLoginOptions = {
    authorizationParameters: {          // AuthorizationParameters from "@auth0/nextjs-auth0/types"
      acr_values: "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
      max_age: 0,                       // number (seconds); 0 forces a fresh challenge
    },
    returnTo: "/dashboard/transfer",
  };
  return auth0.startInteractiveLogin(options); // returns the redirect NextResponse
}
```

Step 3 — gate the sensitive action (Server Component or Server Action), enforced server-side:

```ts
// app/dashboard/transfer/page.tsx
import { redirect } from "next/navigation";
import { auth0 } from "@/lib/auth0";

export default async function TransferPage() {
  const session = await auth0.getSession(); // SessionData | null
  if (!session?.user.amr?.includes("mfa")) {
    redirect("/auth/step-up"); // or the /auth/login?... URL from step 2(a)
  }
  // render the transfer form; re-check the same amr in the Server Action before moving funds
}
```

Step 4 — after Universal Login completes MFA it returns to `returnTo`; `beforeSessionSaved` writes `amr`, the gate now passes, and the transfer runs. A frontend `amr` check is UX only — always enforce on the server.

## Flow 1 — server-side step-up (Route Handler / Server Action)

Force a refresh so the post-login Action runs and can throw `MfaRequiredError`:

```ts
const { token } = await auth0.getAccessToken({ audience: "https://my-api", refresh: true }); // refresh required; default returns cached token
```

Pass `mfa_token` to the MFA page via an **httpOnly cookie**, never the URL:

```ts
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { MfaRequiredError } from "@auth0/nextjs-auth0/server";

try {
  const { token } = await auth0.getAccessToken({ audience: "https://my-api", refresh: true });
  // proceed with token
} catch (error) {
  if (error instanceof MfaRequiredError) {
    const session = await auth0.getSession();
    (await cookies()).set("mfa_token",
      JSON.stringify({ sub: session?.user.sub, token: error.mfa_token }),
      { httpOnly: true, secure: true, sameSite: "lax", maxAge: 300 });
    redirect("/mfa");
  }
  throw error;
}
```

On `/mfa`, read the cookie back. If `auth0.getSession()` returns null (user logged out or session expired), redirect to login and delete the MFA cookie. Otherwise re-check `sub === session.user.sub` to prevent one user completing another's MFA challenge, drive `auth0.mfa.*`, then `(await cookies()).delete("mfa_token")` after a successful verify.

## Flow 2 — MFA management API (`auth0.mfa.*`)

All take `{ mfaToken }`:

- `getAuthenticators({ mfaToken })` → `Authenticator[]`
  `Authenticator: { id: string, authenticatorType: 'otp'|'oob', oobChannel?: 'sms'|'voice'|'auth0'|'email', active: boolean }`
- `enroll({ mfaToken, authenticatorTypes, oobChannels?, phoneNumber?, email? })` — OTP: `["otp"]` → `{ barcodeUri: string, secret: string, recoveryCodes?: string[] }`; OOB: `["oob"]` + `oobChannels` → `{ oobCode: string, bindingMethod?: string }`.
- `challenge({ mfaToken, challengeType: 'oob', authenticatorId })` → `{ oobCode: string, bindingMethod?: string }` (OOB only — not needed for OTP).
- `verify({ mfaToken, otp: string })` / `({ mfaToken, oobCode, bindingCode: string })` / `({ mfaToken, recoveryCode })` → `MfaVerifyResponse` (tokens written to session). `bindingCode` is required when using OOB. When `recoveryCode` is used, the response may include a new `recovery_code` — show it to the user once.

Callable from a Server Component/Action (`auth0.mfa.verify`) or a client component (`import { mfa } from "@auth0/nextjs-auth0/client"`).

## Flow 3 — reactive popup step-up (client components)

`mfa.challengeWithPopup()` calls `window.open()`, so it **must run from a direct user-gesture handler** (a button `onClick`), never from an async `catch`:

```tsx
"use client";
import { getAccessToken, mfa } from "@auth0/nextjs-auth0/client";
import { MfaRequiredError } from "@auth0/nextjs-auth0/errors";

async function handleStepUp() {
  const { token } = await mfa.challengeWithPopup({ audience: "https://api.example.com" });
  await callApi(token);
}
```

Options: `audience` (required), `scope`, `acr_values` (defaults to the PAPE MFA URI), `timeout` (ms, default 60000), `popupWidth`/`popupHeight`. Popup errors: `PopupBlockedError`, `PopupCancelledError`, `PopupTimeoutError`, `PopupInProgressError`, `ExecutionContextError` (called server-side). If a CSP blocks inline scripts, set `cspNonce` on `Auth0Client` or the popup completes but `postMessage` never returns (`PopupTimeoutError`).

## Reading `amr`

v4 persists only a default claim subset, so `amr` is dropped by default. Opt it in on the client with a `beforeSessionSaved` hook — copy the claim from the ID token onto `session.user`, then read `session.user.amr` server-side:

```ts
export const auth0 = new Auth0Client({
  async beforeSessionSaved(session, idToken) {
    if (!idToken) return session;
    const claims = decodeJwt(idToken); // e.g. jose's decodeJwt; idToken is the raw JWT string
    return { ...session, user: { ...session.user, amr: claims.amr } };
  },
});
```

`session` is `SessionData` (`{ user, tokenSet, internal, ... }`); the hook's return type is the same. `amr` lands at `session.user.amr` and survives to `auth0.getSession()`.

## Server error classes

`MfaRequiredError`, `MfaNoAvailableFactorsError`, `MfaTokenExpiredError`, `MfaTokenInvalidError`, `MfaGetAuthenticatorsError`, `MfaEnrollmentError`, `MfaChallengeError`, `MfaVerifyError` (from `@auth0/nextjs-auth0/errors`).
