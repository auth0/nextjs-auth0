# Multi-Factor Authentication (MFA)

Examples for adding Multi-Factor Authentication to your Next.js application with the Auth0 Next.js SDK. This covers step-up authentication, the MFA management API (enrollment, challenge, and verification), and reactive MFA step-up via a browser popup.

- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
  - [Step-up Authentication](#step-up-authentication)
  - [Handling `MfaRequiredError`](#handling-mfarequirederror)
  - [MFA Tenant Configuration](#mfa-tenant-configuration)
  - [MFA Error Types](#mfa-error-types)
  - [Configuration](#configuration)
  - [Session Context](#session-context)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa-1)
  - [Setup & Configuration](#setup--configuration)
  - [Configuration](#configuration-1)
  - [Handling MfaRequiredError](#handling-mfarequirederror-1)
  - [Accessing the MFA API](#accessing-the-mfa-api)
  - [Getting Authenticators](#getting-authenticators)
  - [Enrollment](#enrollment)
  - [Challenge](#challenge)
  - [Verify](#verify)
  - [Complete Flow Examples](#complete-flow-examples)
  - [MFA Tenant Configuration](#mfa-tenant-configuration-1)
  - [MFA Error Handling](#mfa-error-handling)
- [Reactive MFA Step-Up (Popup)](#reactive-mfa-step-up-popup)
  - [Overview](#overview)
  - [Basic Usage](#basic-usage)
  - [Handling MfaRequiredError from Client Components](#handling-mfarequirederror-from-client-components)
  - [Configuration Options](#configuration-options)
  - [CSP Nonce Support](#csp-nonce-support)
  - [Error Handling](#error-handling)

## Multi-Factor Authentication (MFA)

### Step-up Authentication

Step-up authentication is a pattern where an application allows access to some resources with potential sensitive data, but requires the user to authenticate with a stronger mechanism (like MFA) to access others.

The SDK supports handling the `mfa_required` error from Auth0 when an API requires higher security. This typically happens when you use an Auth0 Action or Rule to enforce MFA for specific audiences or scopes.

### Handling `MfaRequiredError`

When you request an Access Token for a resource that requires MFA, Auth0 will return a `403 Forbidden` with an `mfa_required` error code. The SDK automatically catches this and bubbles it up as an `MfaRequiredError`, containing the `mfa_token` needed to resolve the challenge.

You should catch this error in your API routes or Server Actions and forward the `mfa_token` to your client.

**Server Side (API Route):**
```javascript
import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";
import { MfaRequiredError } from "@auth0/nextjs-auth0/server";

export async function GET() {
  try {
    const { token } = await auth0.getAccessToken({
      audience: "https://my-high-security-api",
      refresh: true // Ensure we get a fresh token check
    });
    return NextResponse.json({ token });
  } catch (error) {
    if (error instanceof MfaRequiredError) {
      // Forward the error details to the client
      return NextResponse.json(error.toJSON(), { status: 403 });
    }
    throw error;
  }
}
```

**Client Side:**
When the client receives the 403 with `mfa_required`, you can either redirect the user to a dedicated MFA page or use the popup-based approach to complete MFA without a full-page redirect.

**Option 1: Full-page redirect**
```javascript
const response = await fetch("/api/protected");
if (response.status === 403) {
  const data = await response.json();
  if (data.error === "mfa_required") {
    // Redirect to your MFA page or show MFA prompt
    // Pass the mfa_token to the challenge flow
    window.location.href = `/mfa-challenge?token=${data.mfa_token}`;
  }
}
```

**Option 2: Popup (no redirect)**

Use `mfa.challengeWithPopup()` to complete MFA in a popup without leaving the current page. See [Reactive MFA Step-Up (Popup)](#reactive-mfa-step-up-popup) for full documentation.

### MFA Tenant Configuration

The SDK relies on background token refreshes to maintain user sessions. For these non-interactive requests to succeed, it is important to configure your MFA policies to allow `refresh_token` exchanges without immediate user challenge.

Enforcing **"Always"** or **"All Applications"** in your global Tenant MFA Policy will block these background requests, as they cannot satisfy an interactive MFA challenge.

**Recommended Configuration:**
1. Set Tenant MFA Policy to **"Adaptive"** or **"Never"**.
2. Use **Auth0 Actions** to enforce MFA conditionally (only when specific resources are requested).

**Example Action Code:**
```javascript
exports.onExecutePostLogin = async (event, api) => {
  const grantType = event.request?.body?.grant_type;
  if (grantType === 'refresh_token') {
    // Check if user has enrolled factors
    const enrolledFactors = event.user.multifactor || [];
    
    if (enrolledFactors.length > 0) {
      // Challenge with all available factor types
      // This returns mfa_required error during token endpoint
      api.authentication.challengeWithAny([
        { type: 'otp' },
        { type: 'phone' },
        { type: 'email' },
        { type: 'push-notification' },
        { type: 'recovery-code' }
      ]);
    } else {
      // Prompt enrollment (also returns mfa_required error)
      api.authentication.enrollWithAny([
        { type: 'otp' },
        { type: 'phone' },
        { type: 'email' },
        { type: 'push-notification' }
      ]);
    }
  } else {
    console.log('[MFA Action] Skipping: not refresh_token grant or audience not protected');
  }
};
```
For more information on how to customize MFA flows using post-login Actions, take a look at this [auth0 docs page](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa/customize-mfa-enrollments-universal-login).

### MFA Error Types

| Error Class | Code | When Thrown |
|-------------|------|-------------|
| `MfaRequiredError` | `mfa_required` | Token refresh requires MFA step-up |
| `MfaTokenNotFoundError` | `mfa_token_not_found` | No MFA context for provided token |
| `MfaTokenExpiredError` | `mfa_token_expired` | Encrypted MFA token TTL exceeded |
| `MfaTokenInvalidError` | `mfa_token_invalid` | Token tampered or wrong secret |

### Configuration

Configure MFA token TTL via options or environment variable:

```typescript
// Option 1: Via constructor
const auth0 = new Auth0Client({
  mfaContextTtl: 600 // 10 minutes in seconds
});
```

```bash
# Option 2: Via environment variable
AUTH0_MFA_CONTEXT_TTL=600
```

Default TTL is 300 seconds (5 minutes), matching Auth0's mfa_token expiration.

### Session Context

When MFA is required, the SDK automatically stores MFA context in the session keyed by a hash of the raw token.

> [!NOTE]
> The MFA context is cleaned up automatically when the session is written. Expired contexts (based on `mfaContextTtl`) are removed to prevent session bloat.

## Multi-Factor Authentication (MFA)

> [!NOTE]
> Multi Factor Authentication support via SDKs is currently in Early Access.

The SDK provides comprehensive MFA client APIs to manage multi-factor authentication for your users. The MFA client is accessible via the `mfa` property on both server and client Auth0 instances.

### Setup & Configuration

Before using MFA APIs, configure your Auth0 tenant:

1. **Enable MFA** in [Auth0 Dashboard > Security > Multi-factor Auth](https://manage.auth0.com/#/security/multi-factor-authentication)
2. **Configure Factors**: Enable OTP, SMS, Email, or Push Notification
3. **Set Tenant Policy** to "Adaptive" or "Never" (see [MFA Tenant Configuration](#mfa-tenant-configuration))
4. **Configure MFA Actions** to conditionally enforce MFA for specific resources

### Configuration

Configure MFA token TTL via options or environment variable:

```typescript
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  mfaContextTtl: 600 // 10 minutes in seconds
});
```

```bash
# .env.local
AUTH0_MFA_CONTEXT_TTL=600
```

Default TTL is 300 seconds (5 minutes), matching Auth0's mfa_token expiration.

### Handling MfaRequiredError

When you request an Access Token for a resource that requires MFA, Auth0 will return a `403 Forbidden`. The SDK automatically catches this and throws an `MfaRequiredError` containing the `mfaToken` needed to resolve the challenge.

**`mfa_required` Response:**
```json
{
  "error": "mfa_required",
  "error_description": "Multifactor authentication required",
  "mfa_token": "Fe26...encoded_token"
}
```

Add a catch handler for `MfaRequiredError` around `getAccessToken` call:
```js
try {
  const { token } = await getAccessToken({ audience: "https://api.example.com" });
} catch (error) {
  if (error instanceof MfaRequiredError) {
    // MFA logic here
    // You can pass the `error.mfa_token` to SDK MFA methods
    // Example, redirect to MFA challenge page that contains MFA handling logic
    redirect(`/mfa?token=${error.mfa_token}`);
  }
  throw error;
}
```

### Accessing the MFA API

The MFA API is accessible on both the server and the client to manage authenticators and perform verification.

**On the Server:**

The MFA API is available via the `mfa` property of your `Auth0Client` instance.

```ts
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client();

// Usage in Route Handler or Server Action
const authenticators = await auth0.mfa.getAuthenticators({ mfaToken });
```

**On the Client:**

The MFA API is available as a named export `mfa` from the client entry point.

```ts
// components/mfa-form.tsx
import { mfa } from "@auth0/nextjs-auth0/client";

// Usage in client component
await mfa.verify({ mfaToken, otp });
```

### Getting Authenticators

List all enrolled authenticators for the current user:

```ts
const authenticators = await auth0.mfa.getAuthenticators({ mfaToken });
```

### Enrollment

Enroll new authenticators for MFA. Support includes OTP (TOTP apps), SMS, Email, and Push Notification.

**OTP (Authenticator App)**

```ts
// Returns secret, barcodeUri for QR code
const enrollment = await auth0.mfa.enroll({
  mfaToken,
  authenticatorTypes: ["otp"]
});
```

**SMS**

```ts
const enrollment = await auth0.mfa.enroll({
  mfaToken,
  authenticatorTypes: ["oob"],
  oobChannels: ["sms"],
  phoneNumber: "+15555555555"
});
```

**Email**

```ts
const enrollment = await auth0.mfa.enroll({
  mfaToken,
  authenticatorTypes: ["oob"],
  oobChannels: ["email"],
  email: "user@example.com"
});
```

**Push Notification**

```ts
const enrollment = await auth0.mfa.enroll({
  mfaToken,
  authenticatorTypes: ["oob"],
  oobChannels: ["auth0"]
});
```

### Challenge

Initiate an MFA challenge for OOB authenticators (SMS/Email/Push). OTP authenticators do not require explicit challenge.

```ts
// Returns oobCode and bindingMethod
const challenge = await auth0.mfa.challenge({
  mfaToken,
  challengeType: "oob",
  authenticatorId: "sms|..."
});
```

### Verify

Verify MFA with OTP code, OOB code, or recovery code.

**OTP Verification**

```ts
await auth0.mfa.verify({
  mfaToken,
  otp: "123456"
});
```

**OOB Verification (SMS/Email/Push)**

```ts
await auth0.mfa.verify({
  mfaToken,
  oobCode: challenge.oobCode,
  bindingCode: "123456" // User input
});
```

**Recovery Code Verification**

```ts
await auth0.mfa.verify({
  mfaToken,
  recoveryCode: "ABCD-EFGH-IJKL-MNOP"
});
```

### Complete Flow Examples

For complete implementation guides and best practices, refer to the official Auth0 documentation:

- [Explore multi-factor authentication](https://auth0.com/docs/secure/multi-factor-authentication)
- [Customize Multi-Factor Authentication Pages](https://auth0.com/docs/brand-and-customize/universal-login-pages/customize-mfa-pages)

### MFA Tenant Configuration

The SDK relies on background token refreshes to maintain user sessions. For these non-interactive requests to succeed, configure your MFA policies to allow `refresh_token` exchanges without immediate user challenge.

> [!NOTE]
> Enforcing **"Always"** or **"All Applications"** in your global Tenant MFA Policy will block background token refreshes, as they cannot satisfy an interactive MFA challenge.

**Recommended Configuration:**
Set Tenant MFA Policy to **"Adaptive"** or **"Never"**.

**Example Action Code:**
```javascript
exports.onExecutePostLogin = async (event, api) => {
  // Only trigger on refresh_token grant (step-up)
  if (event.request?.body?.grant_type == "refresh_token") {
    
    if (event.user.enrolledFactors.length) {
      // User has factors enrolled - challenge
      api.authentication.challengeWithAny([
        { type: 'otp' }, 
        { type: 'phone' }, 
        { type: 'push-notification' }, 
        { type: 'email' },
        { type: 'recovery-code' }
      ]);
    } else {
      // No factors enrolled - prompt enrollment
      api.authentication.enrollWithAny([
        { type: 'otp'}, 
        { type: 'phone'},
        { type: 'push-notification' }
      ]);
    }
  }
};
```

### MFA Error Handling

The SDK provides typed error classes for all MFA operations:

| Error Class | Code | When Thrown | Example |
|-------------|------|-------------|---------|
| `MfaRequiredError` | `mfa_required` | Token refresh requires MFA step-up | Accessing protected API |
| `MfaGetAuthenticatorsError` | Various | Failed to list authenticators | Invalid/expired token |
| `MfaEnrollmentError` | Various | Enrollment failed | Unsupported factor type |
| `MfaDeleteAuthenticatorError` | Various | Delete failed | Authenticator not found |
| `MfaChallengeError` | Various | Challenge failed | Invalid authenticator ID |
| `MfaVerifyError` | `invalid_grant` | Verification failed | Invalid OTP code |
| `MfaTokenNotFoundError` | `mfa_token_not_found` | No MFA context for token | Token not in session |
| `MfaTokenExpiredError` | `mfa_token_expired` | Token TTL exceeded | Context expired |
| `MfaTokenInvalidError` | `mfa_token_invalid` | Token tampered or wrong secret | Decryption failed |

## Reactive MFA Step-Up (Popup)

### Overview

The SDK supports **reactive MFA step-up** via a browser popup using Auth0 Universal Login. When an API call fails with `mfa_required`, the client-side `mfa.challengeWithPopup()` method opens a popup window where the user completes MFA through Auth0's Universal Login. After completion, the token is cached in the server-side session and returned directly to the caller — no full-page redirect required.

This is useful for applications that need to protect specific actions (e.g., transferring funds, changing settings) with MFA without disrupting the user's current page state.

**Flow summary:**
1. App calls an API that requires MFA → receives `MfaRequiredError`
2. App calls `mfa.challengeWithPopup({ audience })` → popup opens
3. User completes MFA in the popup via Auth0 Universal Login
4. Popup sends result back via `postMessage` → popup auto-closes
5. SDK retrieves the cached token from the server session
6. `challengeWithPopup()` resolves with the access token

### Basic Usage

```tsx
'use client';

import { mfa, getAccessToken } from '@auth0/nextjs-auth0/client';
import { MfaRequiredError } from '@auth0/nextjs-auth0/errors';
import { useState } from 'react';

export function ProtectedAction() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleAction() {
    try {
      // 1. Try to get an access token for the protected API
      const token = await getAccessToken({
        audience: 'https://api.example.com',
        scope: 'read:sensitive'
      });

      // 2. Use the token to call your API
      const res = await fetch('https://api.example.com/sensitive', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setResult(await res.json());
    } catch (err) {
      if (err instanceof MfaRequiredError) {
        try {
          // 3. MFA required — trigger popup step-up
          const { token } = await mfa.challengeWithPopup({
            audience: 'https://api.example.com',
            scope: 'read:sensitive'
          });

          // 4. Retry with the step-up token
          const res = await fetch('https://api.example.com/sensitive', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setResult(await res.json());
        } catch (popupErr) {
          setError(popupErr.message);
        }
      } else {
        setError(err.message);
      }
    }
  }

  return (
    <div>
      <button onClick={handleAction}>Perform Sensitive Action</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}
```

### Handling MfaRequiredError from Client Components

The client-side `getAccessToken()` helper automatically detects 403 responses with `error: "mfa_required"` and throws `MfaRequiredError`. This allows you to use `instanceof` checks to trigger the popup flow:

```tsx
import { getAccessToken } from '@auth0/nextjs-auth0/client';
import { MfaRequiredError } from '@auth0/nextjs-auth0/errors';

try {
  const token = await getAccessToken({ audience: 'https://api.example.com' });
} catch (err) {
  if (err instanceof MfaRequiredError) {
    // Trigger popup MFA step-up
    const { token } = await mfa.challengeWithPopup({
      audience: 'https://api.example.com'
    });
  }
}
```

> [!NOTE]
> The `MfaRequiredError` detection works for both server-side and client-side `getAccessToken()` calls. On the client, it is reconstructed from the 403 JSON response returned by the `/auth/access-token` endpoint.

### Configuration Options

`challengeWithPopup()` accepts the following options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `audience` | `string` | *(required)* | Target API audience identifier |
| `scope` | `string` | `'openid profile email'` | Space-separated scopes for the token |
| `acr_values` | `string` | `'http://schemas.openid.net/pape/policies/2007/06/multi-factor'` | ACR values sent to Auth0 for step-up policy |
| `returnTo` | `string` | `'/'` | Return URL (used internally by the OAuth flow) |
| `timeout` | `number` | `60000` | Popup timeout in milliseconds |
| `popupWidth` | `number` | `400` | Popup window width in pixels |
| `popupHeight` | `number` | `600` | Popup window height in pixels |

**Example with custom options:**

```tsx
const { token } = await mfa.challengeWithPopup({
  audience: 'https://api.example.com',
  scope: 'openid profile email transfer:funds',
  timeout: 120000,    // 2 minutes
  popupWidth: 500,
  popupHeight: 700
});
```

> [!NOTE]
> Popup timeout is configured per-call only. There is no server-side configuration option or environment variable for this — timeout is a client-side runtime concern. If you need a consistent default across your app, define an application-level constant and pass it to every call.

### CSP Nonce Support

If your application uses a strict Content Security Policy that blocks inline scripts, configure a CSP nonce on the server-side `Auth0Client`:

```typescript
// lib/auth0.ts
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  cspNonce: 'your-generated-nonce'
});
```

The nonce is injected into the `<script>` tag of the popup callback HTML response, making it compliant with `script-src 'nonce-...'` CSP policies.

> [!IMPORTANT]
> The nonce must contain only base64 characters (`A-Za-z0-9+/=-_`). Invalid characters will throw an `InvalidConfigurationError`.

> [!NOTE]
> The `cspNonce` is set at `Auth0Client` construction time and remains static for the lifetime of the instance. Since `Auth0Client` is typically a singleton, this means the same nonce is reused across requests. This still provides protection over `'unsafe-inline'` (the script must know the nonce), but is weaker than per-request nonce rotation. If your security policy requires per-request nonces, you would need to create the `Auth0Client` per-request or use middleware to inject a fresh nonce via a custom header.

If you do **not** configure a `cspNonce` and your CSP blocks inline scripts, the popup will complete the MFA flow but the parent window will never receive the `postMessage`. This manifests as a `PopupTimeoutError` after the configured timeout.

### Error Handling

`challengeWithPopup()` can throw several typed errors. Handle them to provide appropriate user feedback:

```tsx
import { mfa } from '@auth0/nextjs-auth0/client';
import {
  PopupBlockedError,
  PopupCancelledError,
  PopupTimeoutError,
  PopupInProgressError,
  ExecutionContextError
} from '@auth0/nextjs-auth0/errors';

try {
  const { token } = await mfa.challengeWithPopup({
    audience: 'https://api.example.com'
  });
} catch (err) {
  if (err instanceof PopupBlockedError) {
    // Browser blocked the popup — prompt user to allow popups
    alert('Please allow popups for this site and try again.');
  } else if (err instanceof PopupCancelledError) {
    // User closed the popup before completing MFA
    console.log('MFA cancelled by user.');
  } else if (err instanceof PopupTimeoutError) {
    // Popup did not complete within the timeout
    console.log('MFA timed out. Please try again.');
  } else if (err instanceof PopupInProgressError) {
    // Another popup is already open
    console.log('Please complete the current MFA prompt first.');
  } else if (err instanceof ExecutionContextError) {
    // Called from server-side code (SSR, middleware)
    console.error('challengeWithPopup() can only be called in browser context.');
  } else {
    // AccessTokenError or other errors
    console.error('MFA failed:', err.message);
  }
}
```
