# with-custom-token-exchange

A Next.js App Router example demonstrating Custom Token Exchange (CTE) using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Exchange external tokens for Auth0 tokens server-side using [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693).

## What this example covers

- **Basic token exchange** — swap an external token for an Auth0 access token
- **Delegation / impersonation** — pass `actorToken` and `actorTokenType` to represent an entity acting on behalf of the user (RFC 8693 §4.1)
- **`act` claim handling** — decoded from the returned ID token and surfaced on the response and on `session.user.act`
- **Session Transfer Token (STT)** — establish a web session as a customer in a target app without their password (CTE Phase 2)
- **Typed error handling** — `CustomTokenExchangeError` with specific error codes
- Protected `/dashboard` that redirects unauthenticated users to `/`
- Interactive `/cte` page with a form to try the exchange in the browser
- Interactive `/stt` page with a form to request an STT and generate a redirect URL

## Prerequisites

- Node.js 20+
- `pnpm`
- An [Auth0 account](https://auth0.com/signup)
- A CTE profile configured on your Auth0 tenant (see below)

## Auth0 Dashboard Setup

### 1. Create an application

1. Go to **Applications → Create Application**.
2. Choose **Regular Web Application**.
3. Under **Settings**, add:
   - **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
4. Enable the grant type **Token Exchange** on the application.
5. Note the **Domain**, **Client ID**, and **Client Secret**.

### 2. Create a CTE profile

1. Go to **Authentication → Custom Token Exchange** (or use the Management API).
2. Create a profile with the `subject_token_type` you plan to use, e.g. `urn:acme:legacy-token`.
3. Create an Action with the **Custom Token Exchange** trigger to validate the subject token and customise the issued tokens.

### 3. Enable delegation (optional)

For the actor token / delegation flow:

1. Enable the `cte_actor_token` feature flag on your tenant.
2. In your Custom Token Exchange Action, call `api.authentication.setActor({ sub: 'agent|...' })` to set the `act` claim on the issued ID token.

### 4. Enable Session Transfer Token (optional)

For the STT flow (agent establishes a session as a customer in another app):

1. Enable the `cte_session_transfer_token` feature flag on your tenant (contact Auth0 support to enable it).
2. Ensure both the **agent app** and the **target app** are on the same Auth0 tenant.
3. The target app must use `handleLogin()` (or equivalent) which automatically forwards `session_transfer_token` to `/authorize`.
4. Use a **non-localhost** callback URL for the target app. STT redemption is rejected on `localhost` redirect URIs, so run behind a real domain or a tunnel (e.g. Cloudflare Tunnel) and set `APP_BASE_URL` to that URL.

## Configuration

```bash
cp .env.local.example .env.local
```

Fill in:

```bash
# Auth0 tenant domain — e.g. dev-abc123.us.auth0.com
AUTH0_DOMAIN=

# Application credentials (Auth0 Dashboard → Applications → your app → Settings)
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=

# Session encryption key — at least 32 characters
# Generate one with: openssl rand -hex 32
AUTH0_SECRET=

# Base URL of this app
APP_BASE_URL=http://localhost:3000
```

## Running Locally

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

### Custom Token Exchange (`/cte`)

1. Click **Log in** — you are redirected through Auth0 Universal Login and land on `/dashboard`.
2. Your current **access token** is shown on the dashboard — copy it.
3. Click **Try Token Exchange** to go to `/cte`.
4. Paste the access token as the subject token, set the type to `urn:ietf:params:oauth:token-type:access_token`, and click **Exchange token**.
5. The response shows the new `accessToken`, `idToken`, `scope`, and — if your Action sets it — the `act` claim.

### Session Transfer Token (`/stt`)

> Requires a non-localhost callback (see Dashboard Setup step 4). Access the app via that URL, not `http://localhost:3000`.

1. Log in as the **agent** and land on `/dashboard`.
2. Click **Session Transfer** to go to `/stt`.
3. Fill in the customer token, set the token type to your registered CTE profile (e.g. `urn:acme:legacy-token`), and set the target app's login URL (e.g. `https://your-domain/auth/login`). Submit.
4. Copy the returned redirect URL and open it in a **fresh incognito window** (no existing tenant session), within ~60 seconds — the STT is single-use and short-lived.
5. The target app redeems the STT with no login/MFA/consent prompt and establishes a session **as the customer**. Decode the session's ID token: `sub` is the customer and `act.sub` is the agent. No refresh token is issued for an impersonation session.

## How It Works

### Middleware

All auth routes are handled by `proxy.ts`, which passes every request through `auth0.middleware()`. The SDK intercepts `/auth/login`, `/auth/logout`, and `/auth/callback` automatically.

### CTE API Route

`POST /api/cte` is a thin wrapper around `auth0.customTokenExchange()`:

```ts
const result = await auth0.customTokenExchange({
  subjectToken: "eyJ...",
  subjectTokenType: "urn:acme:legacy-token",
  audience: "https://api.example.com",
  // delegation (optional):
  actorToken: "eyJ...",
  actorTokenType: "https://corporate-idp.example.com/id-token",
});
// result.accessToken, result.act, ...
```

`customTokenExchange` is **server-side only** and does NOT modify the user session. It returns tokens that the caller can use directly or store as needed.

### Request flow

```text
POST /api/cte
  → auth0.customTokenExchange(options)
      → validate inputs (subjectToken, subjectTokenType URI, actorTokenType URI)
      → GET https://{domain}/.well-known/openid-configuration
      → POST https://{domain}/oauth/token
            grant_type=urn:ietf:params:oauth:grant-type:token-exchange
            subject_token=...
            subject_token_type=...
            actor_token=...         (if provided)
            actor_token_type=...    (if provided)
      → decode id_token → extract act claim
      → return { accessToken, idToken, refreshToken?, tokenType, expiresIn, scope, act? }
```

### `act` claim

When Auth0 issues an ID token with an `act` claim (set via an Action), the SDK:

1. Decodes the ID token and attaches `act` to the `CustomTokenExchangeResponse`.
2. Preserves `act` in `session.user.act` when the claim appears in a session-creating flow.

```ts
const result = await auth0.customTokenExchange({ ... });
console.log(result.act); // { sub: "agent|abc123" }
```

### Session Transfer Token

An agent calls `requestSessionTransferToken` to obtain a one-shot STT for a customer, then redirects the agent's browser to the target app's login URL carrying the token:

```ts
import { TOKEN_TYPES } from "@auth0/nextjs-auth0/server";

// In a server action / API route running in the **agent** app:
const result = await auth0.requestSessionTransferToken({
  subjectToken: customerIdToken,   // the customer's ID token
  subjectTokenType: TOKEN_TYPES.ID_TOKEN,
  reason: "Investigating ticket #1234",
});

// Redirect the agent's browser to the target app — STT is forwarded as a query param
return auth0.buildSessionTransferRedirect("https://target-app.example.com/auth/login", result);
```

The STT is **one-shot and short-lived (~60 s)**. Never cache it.

The `actor` defaults to the agent session's ID token. Pass `actor` explicitly to override:

```ts
const result = await auth0.requestSessionTransferToken({
  subjectToken: customerIdToken,
  subjectTokenType: TOKEN_TYPES.ID_TOKEN,
  actor: { token: agentIdToken, type: TOKEN_TYPES.ID_TOKEN },
});
```

### Error handling

```ts
import { CustomTokenExchangeErrorCode } from "@auth0/nextjs-auth0/server";

try {
  const result = await auth0.customTokenExchange({ ... });
} catch (err: unknown) {
  const code =
    err && typeof err === "object" && "code" in err
      ? (err as { code: string }).code
      : null;

  switch (code) {
    case CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN:      break;
    case CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE: break;
    case CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN_TYPE:   break;
    case CustomTokenExchangeErrorCode.EXCHANGE_FAILED:
      console.error((err as { cause?: unknown }).cause); // underlying OAuth2 error
      break;
    // STT-specific codes:
    case CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE:          break;
    case CustomTokenExchangeErrorCode.SETACTOR_REQUIRED:          break;
    case CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED:  break;
  }
}
```

## Project Structure

```text
├── app/
│   ├── api/
│   │   ├── cte/
│   │   │   └── route.ts           ← POST /api/cte — calls auth0.customTokenExchange()
│   │   └── stt/
│   │       └── route.ts           ← POST /api/stt — calls auth0.requestSessionTransferToken()
│   ├── cte/
│   │   ├── page.tsx               ← Protected CTE demo page
│   │   └── token-exchange-form.tsx ← Client component — form + response display
│   ├── stt/
│   │   ├── page.tsx               ← Protected STT demo page
│   │   └── session-transfer-form.tsx ← Client component — STT form + redirect URL display
│   ├── dashboard/
│   │   └── page.tsx               ← Protected dashboard — shows session + access token
│   ├── layout.tsx
│   └── page.tsx                   ← Home — redirects to /dashboard if already logged in
├── lib/
│   └── auth0.ts                   ← Auth0Client singleton
└── proxy.ts                       ← Next.js middleware — passes all requests through auth0.middleware()
```
