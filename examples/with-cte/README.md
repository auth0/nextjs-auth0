# with-custom-token-exchange

A Next.js App Router example demonstrating Custom Token Exchange (CTE) using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Exchange external tokens for Auth0 tokens server-side using [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693).

## What this example covers

- **Basic token exchange** — swap an external token for an Auth0 access token
- **Delegation / impersonation** — pass `actorToken` and `actorTokenType` to represent an entity acting on behalf of the user (RFC 8693 §4.1)
- **`act` claim handling** — decoded from the returned ID token and surfaced on the response and on `session.user.act`
- **Typed error handling** — `CustomTokenExchangeError` with specific error codes
- Protected `/dashboard` that redirects unauthenticated users to `/`
- Interactive `/cte` page with a form to try the exchange in the browser

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

1. Click **Log in** — you are redirected through Auth0 Universal Login and land on `/dashboard`.
2. Your current **access token** is shown on the dashboard — copy it.
3. Click **Try Token Exchange** to go to `/cte`.
4. Paste the access token as the subject token, set the type to `urn:ietf:params:oauth:token-type:access_token`, and click **Exchange token**.
5. The response shows the new `accessToken`, `idToken`, `scope`, and — if your Action sets it — the `act` claim.

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

### Error handling

```ts
import { CustomTokenExchangeErrorCode } from "@auth0/nextjs-auth0/errors";

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
  }
}
```

## Project Structure

```text
├── app/
│   ├── api/
│   │   └── cte/
│   │       └── route.ts           ← POST /api/cte — calls auth0.customTokenExchange()
│   ├── cte/
│   │   ├── page.tsx               ← Protected CTE demo page
│   │   └── token-exchange-form.tsx ← Client component — form + response display
│   ├── dashboard/
│   │   └── page.tsx               ← Protected dashboard — shows session + access token
│   ├── layout.tsx
│   └── page.tsx                   ← Home — redirects to /dashboard if already logged in
├── lib/
│   └── auth0.ts                   ← Auth0Client singleton
└── proxy.ts                       ← Next.js middleware — passes all requests through auth0.middleware()
```
