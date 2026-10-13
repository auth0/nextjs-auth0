---
name: passkeys
description: >-
  Passkey (WebAuthn) flows with @auth0/nextjs-auth0 v4: signup, sign-in, and
  My Account enrollment using the server-side auth0.passkey.* API inside App
  Router route handlers or server actions, with navigator.credentials and
  serializeCredential in the browser.
metadata:
  type: sub-skill
  library: nextjs-auth0
  library_version: 4.30.0
requires:
  - nextjs-auth0
---

# @auth0/nextjs-auth0 — Passkeys (v4)

**Minimum version:** `4.22.0` (passkey signup/login + My Account enrollment).

Covers the three passkey flows using the **server-side `auth0.passkey.*` API** inside your own route handlers / server actions. The token exchange and client secret stay on the server; only the WebAuthn call runs in the browser.

For tenant setup (custom domain, passkey grant, connection auth method) see the Auth0 skill hub (`feature:passkeys`).

## Two layers — use the server API here

This SDK ships two ways to build passkeys:

- **Server methods** (`auth0.passkey.*`) — you own the route handlers / server actions. Use when the task asks you to drive the ceremony yourself. **This is what this skill covers.**
- **Client one-call wrappers** (`passkey.signup()` / `passkey.login()` from `@auth0/nextjs-auth0/client`) — shortcut that runs the whole flow in one call. Convenient, but gives you no control over individual steps.

## The ceremony shape (all three flows)

Every flow follows: **server challenge → browser WebAuthn → serialize → server exchange.**

### Signup

```ts
// server (route handler or server action)
import { auth0 } from "@/lib/auth0";

const { authSession, authnParamsPublicKey } = await auth0.passkey.register({
  email,
  name,
  // also accepts: username, phoneNumber, givenName, familyName, nickname,
  //               picture, userMetadata, connection, organization
}); // → PasskeyRegisterResponse
// Send authSession + authnParamsPublicKey to the browser
```

```tsx
"use client";
import { serializeCredential } from "@auth0/nextjs-auth0/client";

// authnParamsPublicKey has base64url binary fields — decode to ArrayBuffers first.
// The SDK does NOT export a decoder, so write a small helper:
function b64urlToBuf(s: string): ArrayBuffer {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    s.length + (4 - (s.length % 4)) % 4, '='));
  return Uint8Array.from(b, c => c.charCodeAt(0)).buffer;
}

const publicKey: PublicKeyCredentialCreationOptions = {
  ...authnParamsPublicKey,
  challenge: b64urlToBuf(authnParamsPublicKey.challenge),
  user: { ...authnParamsPublicKey.user, id: b64urlToBuf(authnParamsPublicKey.user.id) },
  excludeCredentials: authnParamsPublicKey.excludeCredentials?.map(c => ({
    ...c, id: b64urlToBuf(c.id),
  })),
};
const credential = await navigator.credentials.create({ publicKey });
const authResponse = serializeCredential(credential as PublicKeyCredential);
// POST { authSession, authResponse } back to a server action / route
```

```ts
// server: exchange credential for a session
await auth0.passkey.getToken({ authSession, authResponse }); // → Promise<void>
```

### Signup with identifier verification (OTP)

If the connection requires email or phone verification, `register()` returns `verificationRequired` (e.g. `["email"]`). Collect the one-time codes **before** `navigator.credentials.create`, then pass them to `getToken` as `verification`:

The OTP screen and the passkey prompt run in the browser between the two server calls, so use **two Server Actions** called from a `"use client"` component. The browser holds `authSession` and the serialized `authResponse` between calls.

```ts
"use server";
// Both actions return plain objects: error properties thrown from a Server Action do not reach the browser.
// Action 1: challenge = { authSession, authnParamsPublicKey, verificationRequired? }
export async function startSignup(email: string, phoneNumber?: string) {
  try {
    // deliveryMethod ("text" | "voice") is the phone code channel: send it only with phoneNumber
    const challenge = await auth0.passkey.register({ email, ...(phoneNumber && { phoneNumber, deliveryMethod: "text" as const }) });
    return { ok: true as const, challenge };
  } catch (err) {
    if (err instanceof PasskeyRegisterError) return { ok: false as const, error: err.error }; // e.g. too_many_requests
    throw err;
  }
}

// Action 2
export async function completeSignup(authSession: string, authResponse: PasskeyAuthResponse, verification?: PasskeyVerificationCodes) {
  try {
    await auth0.passkey.getToken({ authSession, authResponse, verification });
    return { ok: true as const };
  } catch (err) {
    if (err instanceof MfaRequiredError) {
      // codes accepted, MFA needed. mfa_token is SDK-encrypted, safe to return; the browser
      // continues with the client `mfa` helper (getAuthenticators/challenge/verify), which creates the session
      return { ok: false as const, error: "mfa_required", mfaToken: err.mfa_token };
    }
    if (err instanceof PasskeyGetTokenError) {
      return { ok: false as const, error: err.error, retryable: err.isRetryable, authSession: err.authSession, verificationRequired: err.verificationRequired };
    }
    throw err;
  }
}
```

Client component order: `startSignup`, then show OTP inputs for `verificationRequired`, then `navigator.credentials.create` once, then `completeSignup(authSession, authResponse, codes)` with one code per identifier in `verificationRequired` (e.g. `{ email, phone }`). If `retryable`, re-prompt for `verificationRequired` and call `completeSignup` again with the returned `authSession` (falls back to the original) + the SAME `authResponse`, sending codes only for identifiers still listed (no second biometric prompt). Otherwise a new code will not help: on `too_many_requests` wait and resubmit, on a terminal session restart from `startSignup`. On `mfa_required`, run `mfa.getAuthenticators/challenge/verify({ mfaToken })` in the browser.

With the client wrapper, pass `onVerificationRequired: async ({ verificationRequired, isRetry }) => codes` to `passkey.signup()`, returning one code per listed identifier. It runs before the passkey prompt and again on a wrong code.

### Sign-in

Same shape — replace `register` with `challenge`, and `navigator.credentials.create` with `.get` (decode `challenge` + each `allowCredentials[].id`):

```ts
// server
const { authSession, authnParamsPublicKey } = await auth0.passkey.challenge(); // → PasskeyChallengeResponse
```

```tsx
// browser: decode + navigator.credentials.get + serializeCredential → authResponse
const publicKey: PublicKeyCredentialRequestOptions = {
  ...authnParamsPublicKey,
  challenge: b64urlToBuf(authnParamsPublicKey.challenge),
  allowCredentials: authnParamsPublicKey.allowCredentials?.map(c => ({
    ...c, id: b64urlToBuf(c.id),
  })),
};
const credential = await navigator.credentials.get({ publicKey });
const authResponse = serializeCredential(credential as PublicKeyCredential);
// POST { authSession, authResponse } back to server
```

```ts
// server
await auth0.passkey.getToken({ authSession, authResponse });
```

### Enrollment (signed-in user — adds a passkey to the current account)

Uses the My Account API internally. Requires an MRRT policy on the tenant so the SDK can mint the `create:me:authentication_methods` token from the session refresh token.

```ts
// server
const { authenticationMethodId, authSession, authnParamsPublicKey } =
  await auth0.passkey.enrollmentChallenge(); // → PasskeyEnrollmentChallengeResponse
// Send authenticationMethodId + authSession + authnParamsPublicKey to the browser
```

```tsx
// browser: same decode + navigator.credentials.create + serializeCredential as signup
const authResponse = serializeCredential(credential as PublicKeyCredential);
// POST { authenticationMethodId, authSession, authResponse } back to server
```

```ts
// server
await auth0.passkey.enrollmentVerify({ authenticationMethodId, authSession, authResponse });
// → PasskeyEnrollmentVerifyResponse: the registered auth method { id, type: "passkey", ... }
```

## API reference

| Method | Signature | Returns |
|---|---|---|
| `auth0.passkey.register(options?)` | `PasskeyRegisterOptions?` (incl. `deliveryMethod?: "text" \| "voice"`, phone code channel, send only with `phoneNumber`) | `PasskeyRegisterResponse`: `{ authSession, authnParamsPublicKey, verificationRequired? }` |
| `auth0.passkey.challenge(options?)` | `PasskeyChallengeOptions?` | `PasskeyChallengeResponse` — `{ authSession, authnParamsPublicKey }` |
| `auth0.passkey.getToken(options)` | `{ authSession, authResponse, connection?, organization?, scope?, audience?, verification? }` | `Promise<void>`: sets session |
| `auth0.passkey.enrollmentChallenge(options?)` | `{ connection?, userIdentityId? }?` | `PasskeyEnrollmentChallengeResponse` — `{ authenticationMethodId, authSession, authnParamsPublicKey }` |
| `auth0.passkey.enrollmentVerify(options)` | `{ authenticationMethodId, authSession, authResponse }` | `PasskeyEnrollmentVerifyResponse` |
| `serializeCredential(credential)` | `PublicKeyCredential` | `PasskeyAuthResponse` — JSON-safe, base64url-encoded |

**Pages Router / Middleware overloads:** `register(req, options?)`, `challenge(req, options?)`, `enrollmentChallenge(req, options?)`, `enrollmentVerify(req, options)` take `req: NextRequest`; `getToken(req, res, options)` needs both `NextRequest` and `NextResponse` (wrong arity throws `TypeError`).

## Key gotchas

- **`getToken` credential field is `authResponse`**, not `credential`.
- **No public decoder for `authnParamsPublicKey`** — the SDK doesn't export one; write the tiny base64url helper shown above. Do **not** use `@simplewebauthn` — it double-encodes and breaks the token exchange.
- **Confidential client required** — the server token exchange authenticates with the client secret.
- **Custom domain required**: passkeys will not work on the default `*.auth0.com` domain. The custom domain becomes the passkey `rpId`, and the app must be served from that domain or a subdomain of it (also in local dev; plain `localhost` fails the WebAuthn ceremony).
- **Enrollment requires MRRT** — without the Multi-Resource Refresh Token policy, `enrollmentChallenge` cannot mint the My Account access token.
- **Never spread a request body into `register()` / `getToken()`** from a Server Action or route: the browser could set `connection`, `organization`, `userMetadata`, `audience` or `scope`. Pass only validated fields.
- **`verification` keys are `email` / `phone`**, not `phoneNumber`. Other keys or non-string codes throw `InvalidRequestError` before any request.
- **Only `invalid_grant` with `authSession` is retryable** (`err.isRetryable`, also `is_retryable` in the `/auth/passkey/get-token` error body). `invalid_request` (missing code) is NOT retryable: send a code for every identifier. Never branch on status or `error_description`. On retry reuse the same `authResponse`; never re-run `navigator.credentials.create`.
- **`getToken` can throw `mfa_required`**: continue with the client `mfa` helper (`mfa/SKILL.md`) using the `mfa_token`. The user has no session yet, so `mfa.verify()` (route `/auth/mfa/verify`) creates it; a step-up MFA page or server `auth0.mfa.verify()` fails with no session.
- Do **not** call the server `register`/`challenge` methods from a client component — they are server-only.
