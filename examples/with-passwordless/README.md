# with-passwordless

A Next.js App Router example demonstrating headless passwordless authentication using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Covers all three flows — Email OTP, SMS OTP, and Magic Link — in a single tabbed UI, with a protected dashboard and middleware-based session handling.

## What this example covers

- **Email OTP** — enter email → receive 6-digit code → verify to sign in
- **SMS OTP** — enter phone number → receive 6-digit code → verify to sign in
- **Magic Link** — enter email → receive a link → click it → signed in automatically
- Protected `/dashboard` route that redirects unauthenticated users to `/`
- Typed error handling with `PasswordlessStartError` / `PasswordlessVerifyError`

## Prerequisites

- Node.js 20+
- `pnpm`
- An [Auth0 account](https://auth0.com/signup)

## Auth0 Dashboard Setup

### 1. Create an application

1. Go to **Applications → Create Application**.
2. Choose **Regular Web Application**.
3. Under **Settings**, add the following:
   - **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
   - **Allowed Web Origins**: `http://localhost:3000`
4. Save changes and note down the **Domain**, **Client ID**, and **Client Secret**.

### 2. Enable a Passwordless connection

1. Go to **Authentication → Passwordless**.
2. Enable **Email** (for Email OTP and Magic Link) and/or **SMS** (for SMS OTP).
   - For Email: configure the OTP expiry and message template as needed.
   - For SMS: configure your SMS provider (Twilio or similar) and message template.
3. Go to **Applications → \<your app\> → Connections** and enable the passwordless connection(s) you just configured.

> **Note:** Email OTP and Magic Link both use the **Email** passwordless connection on Auth0. The `send` parameter (`"code"` vs `"link"`) controls which flow is triggered.

## Configuration

Create a `.env.local` file in this directory:

```bash
cp .env.local.example .env.local   # if an example file exists, otherwise create it manually
```

Fill in the following variables:

```bash
# Auth0 tenant domain — e.g. dev-abc123.us.auth0.com
AUTH0_DOMAIN=

# Application credentials (from Auth0 Dashboard → Applications → your app → Settings)
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=

# Session encryption key — any random string of at least 32 characters
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

Open [http://localhost:3000](http://localhost:3000). You will see three tabs — **Email OTP**, **SMS OTP**, and **Magic Link**. Sign in using any flow and you will be redirected to `/dashboard`.

## How It Works

The SDK mounts all auth routes through a single catch-all handler at `app/auth/[auth0]/route.ts`. Two routes are used by this example:

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/auth/passwordless/start` | Calls Auth0 to send an OTP or magic link to the user |
| `POST` | `/auth/passwordless/verify` | Verifies the OTP, exchanges it for tokens, and sets the session cookie |
| `GET` | `/auth/callback` | Handles the redirect after a magic link is clicked (standard OAuth callback) |

The `<PasswordlessForm />` client component drives all three flows using the `passwordless` singleton from `@auth0/nextjs-auth0/client`:

```tsx
import { passwordless } from "@auth0/nextjs-auth0/client";
import { PasswordlessStartError, PasswordlessVerifyError } from "@auth0/nextjs-auth0/errors";

// Email OTP — Step 1: send code
await passwordless.start({ connection: "email", email, send: "code" });

// Email OTP — Step 2: verify code (session cookie set automatically on success)
await passwordless.verify({ connection: "email", email, verificationCode: code });

// SMS OTP
await passwordless.start({ connection: "sms", phoneNumber });
await passwordless.verify({ connection: "sms", phoneNumber, verificationCode: code });

// Magic link — no verify step; Auth0 redirects to /auth/callback on click
await passwordless.start({ connection: "email", email, send: "link" });
```

Session protection on `/dashboard` is handled by `auth0.getSession()` in the Server Component — if no session exists it redirects to `/`. The `middleware.ts` keeps the session rolling on every request.

## Project Structure

```
├── app/
│   ├── auth/
│   │   └── [auth0]/route.ts    ← Mounts all SDK routes (login, callback, logout, passwordless, etc.)
│   ├── dashboard/
│   │   └── page.tsx            ← Protected page — shows user profile, email, phone
│   ├── layout.tsx              ← Root layout
│   └── page.tsx                ← Home page with the tabbed passwordless form
├── components/
│   └── passwordless-form.tsx   ← Tabbed UI: Email OTP / SMS OTP / Magic Link
├── lib/
│   └── auth0.ts                ← Auth0Client singleton (shared across app and middleware)
└── middleware.ts               ← Runs auth0.middleware() on every request for session refresh
```
