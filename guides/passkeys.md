# Passkey Authentication

Auth0 supports passkey (WebAuthn) authentication. Users sign in with device biometrics or a PIN instead of a password. The private key never leaves the device's secure enclave.

The SDK exposes:
- **Built-in route handlers** served via `auth0.handler` (catch-all route) or `auth0.middleware` (proxy pattern) that handle the full passkey lifecycle server-side
- **`auth0.passkey`**: a server-side client for calling challenge/verify from Server Actions or API routes directly
- **`passkey`** from `@auth0/nextjs-auth0/client`: a client-side singleton that drives the full WebAuthn ceremony and calls the route handlers

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [Universal Login (Recommended)](#universal-login-recommended)
- [Auth0 Setup](#auth0-setup)
- [Route Handler Setup](#route-handler-setup)
- [Client-Side Usage](#client-side-usage)
- [Server-Side (Headless) Usage](#server-side-headless-usage)
- [Signup with Identifier Verification](#signup-with-identifier-verification)
- [Error Handling](#error-handling)
- [Passkey Enrollment](#passkey-enrollment)
  - [Auth0 Setup for Enrollment](#auth0-setup-for-enrollment)
  - [Enrollment Route Handlers](#enrollment-route-handlers)
  - [Server-Side Enrollment](#server-side-enrollment)
  - [Client-Side Enrollment](#client-side-enrollment)
- [Route Configuration](#route-configuration)
- [Error Types](#error-types)

## Universal Login (Recommended)

The simplest approach: redirect to Auth0's Universal Login page with passkey support enabled. Auth0 handles the entire WebAuthn ceremony on its hosted page, so your app needs no custom form.

```tsx
<a href="/auth/login">Sign in</a>
```

After the user completes the flow, Auth0 redirects to `/auth/callback` and the SDK creates a session, identical to a standard OAuth callback.

> [!NOTE]
> The rest of this section documents the **custom (headless) API** (`auth0.passkey` and the `passkey` client singleton) for cases where you need full control over the login UI.

## Auth0 Setup

Before using passkeys, enable passkey support in the Auth0 Dashboard:

1. Go to **Authentication → Database →** your connection **→ Authentication Methods**, open **Passkey → Configure** and check **Enable passkeys**.
2. Go to **Applications → \<your app\> → Settings → Advanced Settings → Grant Types** and enable the **Passkey** grant. The token exchange fails without it.
3. In **Applications → \<your app\> → Settings**, ensure:
   - **Allowed Callback URLs** includes your app's callback URL
   - **Allowed Web Origins** includes your app's origin (required for WebAuthn's `rpId` check)
4. **A custom domain is required.** Passkeys are bound to an origin (domain). A [custom domain](https://auth0.com/docs/customize/custom-domains) must be configured; passkeys will not work on the default `*.auth0.com` domain. The custom domain becomes the passkey `rpId`, and your app must be served from that domain or a subdomain of it, so plain `localhost` does not work.

Read [the Auth0 docs](https://auth0.com/docs/authenticate/database-connections/passkeys) to learn more about passkeys.

> [!IMPORTANT]
> The `/oauth/token` passkey grant requires a JSON request body (`Content-Type: application/json`) because `authn_response` must be a nested object. The SDK handles this automatically.

> [!NOTE]
> Default database connections require an `email` field in the signup options. Connections with custom `attributes` configuration may not require it. Auth0 will return an error if a required field is missing.

## Route Handler Setup

The SDK registers three handlers automatically when you mount `auth0.handler`:

| Method | Default Path | Purpose |
|--------|--------------|---------|
| `POST` | `/auth/passkey/register` | Get a WebAuthn credential creation challenge for a new user |
| `POST` | `/auth/passkey/challenge` | Get a WebAuthn credential assertion challenge for an existing user |
| `POST` | `/auth/passkey/get-token` | Verify the WebAuthn credential and create a session |

**App Router**: add `POST` to your existing catch-all auth route:

```typescript
// app/auth/[auth0]/route.ts
import { auth0 } from "@/lib/auth0";

export const GET = auth0.handler;
export const POST = auth0.handler;
```

**Pages Router**: mount the handler in your API route:

```typescript
// pages/api/auth/[auth0].ts
import { auth0 } from "@/lib/auth0";

export default auth0.handler;
```

## Client-Side Usage

Import the `passkey` singleton from `@auth0/nextjs-auth0/client`. Use `signup()` for new users and `login()` for returning users. Each method handles the full WebAuthn ceremony internally (challenge fetch → `navigator.credentials.create/get()` → verify).

```tsx
"use client";
import { useState } from "react";
import { passkey } from "@auth0/nextjs-auth0/client";

export function PasskeyForm() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await passkey.signup({ email, name: email });
      window.location.href = "/dashboard";
    } catch (err: any) {
      if (err.error === "webauthn_error") {
        setError(err.error_description ?? "Passkey operation was cancelled.");
      } else {
        setError(err.error_description ?? "Something went wrong.");
      }
    }
  }

  async function handleLogin() {
    setError(null);
    try {
      await passkey.login();
      window.location.href = "/dashboard";
    } catch (err: any) {
      if (err.error === "webauthn_error") {
        setError(err.error_description ?? "Passkey operation was cancelled.");
      } else {
        setError(err.error_description ?? "Something went wrong.");
      }
    }
  }

  return (
    <>
      <form onSubmit={handleSignup}>
        {error && <p>{error}</p>}
        <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="Email" />
        <button type="submit">Sign up with passkey</button>
      </form>
      <button onClick={handleLogin}>Sign in with passkey</button>
    </>
  );
}
```

**Step-by-step (full control):**

For cases where you need to inspect the challenge or credential before verifying, you can call each step individually:

```typescript
"use client";
import { serializeCredential } from "@auth0/nextjs-auth0/client";
import type {
  PasskeyCreationOptionsJSON,
  PasskeyRequestOptionsJSON
} from "@auth0/nextjs-auth0/types";
// Server Actions from "Server-Side (Headless) Usage" below
import { getLoginChallenge, getSignupChallenge, verifyPasskey } from "./actions";

// The SDK does not export a decoder for authnParamsPublicKey's base64url fields.
const toBuffer = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0)
  ).buffer;

const toCreationOptions = (pk: PasskeyCreationOptionsJSON) =>
  ({
    ...pk,
    challenge: toBuffer(pk.challenge),
    user: { ...pk.user, id: toBuffer(pk.user.id) },
    excludeCredentials: pk.excludeCredentials?.map((c) => ({ ...c, id: toBuffer(c.id) }))
  }) as PublicKeyCredentialCreationOptions;

const toRequestOptions = (pk: PasskeyRequestOptionsJSON) =>
  ({
    ...pk,
    challenge: toBuffer(pk.challenge),
    allowCredentials: pk.allowCredentials?.map((c) => ({ ...c, id: toBuffer(c.id) }))
  }) as PublicKeyCredentialRequestOptions;

// Signup, step by step
const signup = await getSignupChallenge({ email: "user@example.com", name: "Jane" });
const created = await navigator.credentials.create({ publicKey: toCreationOptions(signup.authnParamsPublicKey) });
if (!created) throw new Error("No passkey was created");
await verifyPasskey(signup.authSession, serializeCredential(created as PublicKeyCredential));

// Login, step by step
const login = await getLoginChallenge();
const asserted = await navigator.credentials.get({ publicKey: toRequestOptions(login.authnParamsPublicKey) });
if (!asserted) throw new Error("No passkey was selected");
await verifyPasskey(login.authSession, serializeCredential(asserted as PublicKeyCredential));
```

> [!NOTE]
> `authnParamsPublicKey` is returned as a plain object with base64url-encoded buffers. When using the step-by-step API you must decode the `challenge`, `user.id`, `excludeCredentials[].id` and `allowCredentials[].id` fields back to `ArrayBuffer` before passing them to the WebAuthn API. The one-call `signup()` and `login()` methods handle this automatically.

## Server-Side (Headless) Usage

Use `auth0.passkey` directly in **Server Actions** or **API Routes** when you want full control over the request/response cycle.

**App Router (Server Action):**

```typescript
"use server";
import { auth0 } from "@/lib/auth0";
import type {
  PasskeyAuthResponse,
  PasskeyRegisterOptions
} from "@auth0/nextjs-auth0/types";

export async function getSignupChallenge(options: PasskeyRegisterOptions) {
  return auth0.passkey.register(options);
}

export async function getLoginChallenge() {
  return auth0.passkey.challenge();
}

// Sets the session cookie. See "Signup with Identifier Verification" for
// returning errors as plain objects.
export async function verifyPasskey(
  authSession: string,
  authResponse: PasskeyAuthResponse
) {
  await auth0.passkey.getToken({ authSession, authResponse });
}
```

**Pages Router (API Route):**

```typescript
import { auth0 } from "@/lib/auth0";
import type { NextApiRequest, NextApiResponse } from "next";
import { NextRequest, NextResponse } from "next/server";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const host = Array.isArray(req.headers.host) ? req.headers.host[0] : req.headers.host;
  const proto = (Array.isArray(req.headers["x-forwarded-proto"])
    ? req.headers["x-forwarded-proto"][0]
    : req.headers["x-forwarded-proto"]) ?? "https";
  const nextReq = new NextRequest(
    host ? new URL(req.url!, `${proto}://${host}`) : new URL(req.url!, "https://localhost"),
    { method: req.method, headers: req.headers as HeadersInit }
  );
  const nextRes = new NextResponse();

  await auth0.passkey.getToken(nextReq, nextRes, {
    authSession: req.body.authSession,
    authResponse: req.body.authResponse
  });

  const cookies = nextRes.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
  res.status(200).json({ success: true });
}
```

## Signup with Identifier Verification

> **Note:** Identifier verification on passkey signup is in Early Access. Please contact Auth0 Support to get it enabled for your tenant.

When a database connection requires the user's email or phone to be verified, Auth0 asks for a one-time code during passkey signup. The signup challenge lists the identifiers to verify in `verificationRequired` (`"email"`, `"phone"` or both). Collect the codes **before** creating the passkey, then send them with the token exchange. If no verification is required, `verificationRequired` is absent and the flow is unchanged.

**Prerequisites:** identifier verification on passkey signup must be enabled for your tenant (it is off by default), and verification must be turned on for the `email` and/or `phone` identifier of a database connection that has passkeys enabled (**Authentication → Database →** your connection **→ Attributes →** the identifier **→ Configure**: set the email Verification Method to **One-Time Password (OTP)** and turn on **Verify email on sign up**, or **Verify phone on signup**, which needs a phone provider). While it is off, `register()` never returns `verificationRequired` and the flow is unchanged, so you can ship this code first.

**Client-side (one call):** pass `onVerificationRequired` to `passkey.signup()`. The SDK calls it before the passkey prompt and resolves the codes you return. If a code is wrong, it calls it again with `isRetry: true` and the identifiers still pending, then resubmits the same passkey, so the user is not asked for their biometric twice.

```tsx
"use client";
import { passkey } from "@auth0/nextjs-auth0/client";

await passkey.signup({
  email,
  phoneNumber,
  deliveryMethod: "text", // or "voice", channel for the phone code; omit without phoneNumber
  onVerificationRequired: async ({ verificationRequired, isRetry }) => {
    // Show one OTP input per identifier, e.g. ["email", "phone"]
    const codes = await showOtpForm(verificationRequired, { isRetry });
    return codes; // { email: "123456", phone: "654321" }
  }
});
```

Without `onVerificationRequired`, a signup that requires verification throws `PasskeyGetTokenError` with `error: "verification_required"` before any passkey is created.

**Server-side (headless):** the OTP screen and the passkey prompt run in the browser between `register()` and `getToken()`, so split the flow into two Server Actions and drive them from a client component. The browser holds `authSession` between the two calls.

```typescript
// app/signup/actions.ts
"use server";
import { auth0 } from "@/lib/auth0";
import type {
  PasskeyAuthResponse,
  PasskeyVerificationCodes
} from "@auth0/nextjs-auth0/types";
import {
  PasskeyGetTokenError,
  PasskeyRegisterError
} from "@auth0/nextjs-auth0/errors";
import { MfaRequiredError } from "@auth0/nextjs-auth0/server";

// Both actions return plain objects: properties on errors thrown from a
// Server Action do not reach the browser.

// Step 1: get the signup challenge. verificationRequired tells the UI which OTP inputs to show.
// Every call sends new codes, so rate-limit it (see the security notes below).
export async function startSignup(email: string, phoneNumber?: string) {
  try {
    const challenge = await auth0.passkey.register({
      email,
      // deliveryMethod is the phone code channel ("text" or "voice"): send it
      // only with a phone number, omit it for email-only verification.
      ...(phoneNumber && { phoneNumber, deliveryMethod: "text" as const })
    });
    return { ok: true as const, challenge };
  } catch (err) {
    if (err instanceof PasskeyRegisterError) {
      return { ok: false as const, error: err.error };
    }
    throw err;
  }
}

// Step 2: exchange the passkey and the codes for a session.
export async function completeSignup(
  authSession: string,
  authResponse: PasskeyAuthResponse,
  verification?: PasskeyVerificationCodes
) {
  try {
    await auth0.passkey.getToken({ authSession, authResponse, verification });
    return { ok: true as const };
  } catch (err) {
    if (err instanceof MfaRequiredError) {
      // The codes were accepted and the user must complete MFA. err.mfa_token
      // is encrypted by the SDK, so it is safe to return. The browser continues
      // with the client `mfa` helper, which creates the session when MFA succeeds.
      return {
        ok: false as const,
        error: "mfa_required",
        mfaToken: err.mfa_token
      };
    }
    if (err instanceof PasskeyGetTokenError) {
      return {
        ok: false as const,
        error: err.error,
        retryable: err.isRetryable,
        // Retry with this session. Auth0 echoes the original today.
        authSession: err.authSession,
        verificationRequired: err.verificationRequired
      };
    }
    throw err;
  }
}
```

```tsx
// app/signup/signup-form.tsx
"use client";
import { useState } from "react";
import { mfa, serializeCredential } from "@auth0/nextjs-auth0/client";
import type {
  PasskeyAuthResponse,
  PasskeyCreationOptionsJSON,
  PasskeyRegisterResponse,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier
} from "@auth0/nextjs-auth0/types";
import { completeSignup, startSignup } from "./actions";

// authnParamsPublicKey carries base64url fields. The SDK does not export a decoder.
const toBuffer = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0)
  ).buffer;

const toCreationOptions = (
  pk: PasskeyCreationOptionsJSON
): PublicKeyCredentialCreationOptions =>
  ({
    ...pk,
    challenge: toBuffer(pk.challenge),
    user: { ...pk.user, id: toBuffer(pk.user.id) },
    excludeCredentials: pk.excludeCredentials?.map((c) => ({
      ...c,
      id: toBuffer(c.id)
    }))
  }) as PublicKeyCredentialCreationOptions;

export function SignupForm() {
  const [challenge, setChallenge] = useState<PasskeyRegisterResponse>();
  const [pending, setPending] = useState<PasskeyVerificationIdentifier[]>([]);
  const [authResponse, setAuthResponse] = useState<PasskeyAuthResponse>();
  const [mfaToken, setMfaToken] = useState<string>();
  const [message, setMessage] = useState<string>();

  function reset(text: string) {
    setChallenge(undefined);
    setAuthResponse(undefined);
    setPending([]);
    setMessage(text);
  }

  async function onEmail(email: string) {
    const result = await startSignup(email);
    if (!result.ok) {
      setMessage(
        result.error === "too_many_requests"
          ? "Too many attempts. Wait a moment and try again."
          : "Signup is not available right now."
      );
      return;
    }
    setChallenge(result.challenge);
    if (result.challenge.verificationRequired) {
      setPending(result.challenge.verificationRequired);
    } else {
      await finish(result.challenge); // no OTP needed
    }
  }

  // Called with the codes from the OTP screen, or with none when not required.
  async function finish(c = challenge!, codes?: PasskeyVerificationCodes) {
    // Create the passkey once. On a wrong code, resubmit the same credential.
    let response = authResponse;
    if (!response) {
      let credential: Credential | null;
      try {
        credential = await navigator.credentials.create({
          publicKey: toCreationOptions(c.authnParamsPublicKey)
        });
      } catch {
        // NotAllowedError: the user cancelled or the prompt timed out.
        // The codes were not used yet, so let them try the prompt again.
        setMessage("Passkey creation was cancelled. Try again.");
        return;
      }
      if (!credential) {
        setMessage("No passkey was created. Try again.");
        return;
      }
      response = serializeCredential(credential as PublicKeyCredential);
      setAuthResponse(response);
    }

    const result = await completeSignup(c.authSession, response, codes);
    if (result.ok) {
      window.location.assign("/");
    } else if (result.mfaToken) {
      // Continue with MFA in the browser. mfa.verify() creates the session.
      const [authenticator] = (
        await mfa.getAuthenticators({ mfaToken: result.mfaToken })
      ).filter((a) => a.active);
      if (!authenticator) {
        // Enroll one first with mfa.enroll(), see guides/mfa.md.
        return;
      }
      await mfa.challenge({
        mfaToken: result.mfaToken,
        challengeType: authenticator.authenticatorType,
        authenticatorId: authenticator.id
      });
      setMfaToken(result.mfaToken); // show the MFA code input
    } else if (
      "retryable" in result &&
      result.retryable &&
      result.verificationRequired
    ) {
      // Keep the credential; send codes only for the identifiers still listed.
      setChallenge({ ...c, authSession: result.authSession ?? c.authSession });
      setPending(result.verificationRequired); // show the OTP screen again
      setMessage("That code was not right. Try again.");
    } else if (result.error === "too_many_requests") {
      // The signup session may still be alive: keep the state and let the user resubmit.
      setMessage("Too many attempts. Wait a moment and try again.");
    } else {
      reset("Signup could not be completed. Please start again.");
    }
  }

  if (mfaToken) {
    // Render an MFA code input. On submit:
    //   await mfa.verify({ mfaToken, otp: code }); window.location.assign("/");
    // SMS and email authenticators use oobCode + bindingCode, see guides/mfa.md.
  }
  if (pending.length > 0) {
    // Render one OTP input per entry in `pending` ("email", "phone"), then call
    // finish(challenge, { email: "123456", phone: "654321" }) on submit.
  }
  // Otherwise render the email form and call onEmail(email) on submit.
}
```

The `verification` keys are `email` and `phone`. Note that the phone key is `phone`, not `phoneNumber`. Any other key, or a code that is not a string, throws `InvalidRequestError` before a request is sent. Blank codes are treated as not provided.

**Retrying after an error:**

Branch on `isRetryable`, never on the HTTP status or `error_description`. A wrong code and a failure that ends the attempt return the same status and description; only the presence of `authSession` tells them apart.

| Error | `isRetryable` | What to do |
|-------|---------------|------------|
| `invalid_grant` with `authSession` set | `true` | A code was wrong. Re-prompt only for the identifiers in `verificationRequired` (codes that were right are remembered), then resubmit with `authSession` from the error and the same credential. |
| `invalid_grant` without `authSession` | `false` | Too many wrong codes, expired codes, or an unknown or already used session. Restart from `register()`. |
| `invalid_request` | `false` | A required code was missing. This is an integration bug: always send a code for every identifier in `verificationRequired`. |
| `MfaRequiredError` (`mfa_required`) | n/a | The codes were accepted and the user must complete MFA. Pass the encrypted `mfa_token` to the client `mfa` helper (`getAuthenticators`, `challenge`, `verify`); `mfa.verify()` creates the session. Do not use a step-up MFA page here: the user has no session yet. |
| `too_many_requests` | `false` | Rate limited. Wait before retrying. |
| Any 5xx | `false` | A generic server error, not a verification state. Wait briefly and try again, or restart. |

> [!NOTE]
> The signup session lasts 15 minutes when verification is required, and each code can be used once. If the connection drops after Auth0 accepts the codes but before your app receives the tokens, the session is gone and the user must restart signup.

**Sending new codes:** every `register()` call sends new codes and returns a new `authSession` and `authnParamsPublicKey`. To resend a code, call `register()` again **before** the passkey is created, and use only the values from the latest response.

When using the built-in `/auth/passkey/get-token` route, an error response includes `is_retryable`, and a retryable one also includes `auth_session` and `verification_required` so the browser can re-prompt. The one-call `passkey.signup()` handles this for you.

**Security and operational notes:**

- Rate-limit the action or route that calls `register()`, per IP address and per email address or phone number. Every call sends a message, so an open endpoint can be used to send codes to anyone. Do not rely only on Auth0's limits.
- Never log the codes, the `authSession` or the credential. `PasskeyGetTokenError` keeps `authSession` out of its message and `toJSON()`, but it is on `err.authSession` and `err.cause.auth_session`, so do not log the whole error object.
- Send one `getToken()` request at a time per `authSession`, for example by disabling the submit button while a request is pending. Parallel requests can use up the allowed attempts.
- Pass only the fields you validated to `register()` and `getToken()`. Do not spread a request body into them, or the browser could choose `connection`, `organization`, `userMetadata`, `audience` or `scope`.

## Error Handling

Passkey errors expose `error` (the error code) and `error_description`. Check `error === "webauthn_error"` to distinguish user cancellation or device capability issues from server errors.

```typescript
import {
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError
} from "@auth0/nextjs-auth0/errors";

try {
  await passkey.signup({ email });
} catch (err) {
  if (err instanceof PasskeyRegisterError) {
    // err.error: e.g. 'passkeys_not_enabled', 'invalid_request'
    // err.error_description: human-readable message
  }
  if (err instanceof PasskeyGetTokenError) {
    if (err.error === "webauthn_error") {
      // User cancelled the browser dialog, or device doesn't support passkeys
    }
  }
}

try {
  await passkey.login();
} catch (err) {
  if (err instanceof PasskeyChallengeError) {
    // Challenge request failed
  }
  if (err instanceof PasskeyGetTokenError) {
    if (err.error === "webauthn_error") {
      // User cancelled or device doesn't support passkeys
    }
  }
}
```

## Passkey Enrollment

Authenticated users can enroll additional passkeys, useful for backup devices or shared computers. Enrollment uses the Auth0 MyAccount API and requires an active session.

### Auth0 Setup for Enrollment

1. Configure a **Multi-Resource Refresh Token (MRRT)** policy for your application:
   - **Audience**: `https://{your-domain}/me/`
   - **Scope**: `create:me:authentication_methods`
2. The SDK exchanges the session refresh token for a MyAccount-scoped access token automatically at call time.

### Enrollment Route Handlers

Two additional routes are registered automatically:

| Method | Default Path | Purpose |
|--------|--------------|---------|
| `POST` | `/auth/passkey/enrollment-challenge` | Request a WebAuthn creation challenge for the current user (requires session) |
| `POST` | `/auth/passkey/enrollment-verify` | Verify the attestation and complete enrollment (requires session) |

### Server-Side Enrollment

Call `auth0.passkey.enrollmentChallenge()` and `auth0.passkey.enrollmentVerify()` directly from a Server Action or API Route:

```typescript
"use server";
import { auth0 } from "@/lib/auth0";
import type { PasskeyEnrollmentVerifyOptions } from "@auth0/nextjs-auth0";

export async function getEnrollmentChallenge() {
  // Requires an active session; throws PasskeyEnrollmentChallengeError if not authenticated
  return auth0.passkey.enrollmentChallenge();
}

export async function verifyEnrollment(options: PasskeyEnrollmentVerifyOptions) {
  return auth0.passkey.enrollmentVerify(options);
}
```

### Client-Side Enrollment

Call the enrollment route handlers from a client component:

```tsx
"use client";
import { useState } from "react";

export function PasskeyEnrollForm() {
  const [error, setError] = useState<string | null>(null);

  async function handleEnroll() {
    // Step 1: get enrollment challenge
    const challengeRes = await fetch("/auth/passkey/enrollment-challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({})
    });
    if (!challengeRes.ok) {
      const err = await challengeRes.json().catch(() => ({}));
      setError(err.error_description ?? "Failed to get enrollment challenge");
      return;
    }
    const { authenticationMethodId, authSession, authnParamsPublicKey } = await challengeRes.json();

    // Step 2: WebAuthn ceremony
    const credential = await navigator.credentials.create({
      publicKey: toCreationOptions(authnParamsPublicKey) // helper from "Step-by-step" above
    }) as PublicKeyCredential | null;
    if (!credential) return;

    // Step 3: verify enrollment
    const verifyRes = await fetch("/auth/passkey/enrollment-verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ authenticationMethodId, authSession, authResponse: serializeCredential(credential) })
    });
    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}));
      setError(err.error_description ?? "Enrollment verification failed");
      return;
    }
    const method = await verifyRes.json(); // PasskeyAuthenticationMethod
    console.log("Enrolled:", method.id, method.key_id);
  }

  return <button onClick={handleEnroll}>Enroll a passkey</button>;
}
```

> [!NOTE]
> `authnParamsPublicKey` contains base64url-encoded `ArrayBuffer` fields (`challenge`, `user.id`, `excludeCredentials[].id`). You must decode them before passing to `navigator.credentials.create()`. See `examples/with-passkeys/components/passkey-enroll-form.tsx` for a complete implementation.

## Route Configuration

The default route paths can be overridden with environment variables:

```bash
# .env.local
NEXT_PUBLIC_PASSKEY_REGISTER_ROUTE=/auth/passkey/register
NEXT_PUBLIC_PASSKEY_CHALLENGE_ROUTE=/auth/passkey/challenge
NEXT_PUBLIC_PASSKEY_GET_TOKEN_ROUTE=/auth/passkey/get-token
NEXT_PUBLIC_PASSKEY_ENROLLMENT_CHALLENGE_ROUTE=/auth/passkey/enrollment-challenge
NEXT_PUBLIC_PASSKEY_ENROLLMENT_VERIFY_ROUTE=/auth/passkey/enrollment-verify
```

Because these variables are prefixed with `NEXT_PUBLIC_`, they are inlined by the Next.js bundler and available on the client without an extra API call.

## Error Types

| Error Class | `error` Code | When Thrown |
|-------------|--------------|-------------|
| `PasskeyRegisterError` | `passkeys_not_enabled` | Passkeys not enabled for the application |
| `PasskeyRegisterError` | `invalid_request` | Missing or malformed body field |
| `PasskeyRegisterError` | `client_error` | Network failure or unparseable response |
| `PasskeyRegisterError` | `too_many_requests` | Signup challenge rate limited (route returns 429) |
| `PasskeyChallengeError` | `invalid_request` | Missing or malformed body field |
| `PasskeyChallengeError` | `client_error` | Network failure or unparseable response |
| `PasskeyChallengeError` | `too_many_requests` | Login challenge rate limited (route returns 429) |
| `PasskeyGetTokenError` | `webauthn_error` | User cancelled the browser dialog, or device doesn't support passkeys |
| `PasskeyGetTokenError` | `invalid_grant` | Invalid or replayed passkey assertion, or a wrong verification code (check `isRetryable`) |
| `PasskeyGetTokenError` | `verification_required` | Signup requires verification codes but no `onVerificationRequired` callback was given |
| `PasskeyGetTokenError` | `too_many_requests` | Token exchange rate limited (route returns 429) |
| `PasskeyGetTokenError` | `client_error` | Network failure or unparseable response |
| `PasskeyEnrollmentChallengeError` | N/A | No active session when enrollment challenge was requested |
| `PasskeyEnrollmentChallengeError` | N/A | Enrollment not enabled on the tenant |
| `PasskeyEnrollmentChallengeError` | N/A | Auth0 did not return a `Location` header |
| `PasskeyEnrollmentVerifyError` | N/A | No active session when enrollment verify was called |
| `PasskeyEnrollmentVerifyError` | N/A | Invalid or replayed attestation |
