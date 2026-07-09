# with-passwordless-db

A Next.js App Router example demonstrating passwordless OTP authentication against a standard **database connection** using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Users sign in with a one-time code sent to their email or phone — no password required — using Auth0's new `/otp/challenge` endpoint that works with any database connection configured with `email_otp` or `phone_otp`.

## What this example covers

- **Email OTP** — enter email → receive 6-digit code → verify to sign in (supports new user signup)
- **Phone OTP** — enter phone number → receive 6-digit code → verify to sign in (existing users only)
- **MFA** — full challenge flow when MFA is configured: TOTP enrollment with QR code, or challenge an existing TOTP/OOB authenticator
- Protected `/dashboard` route that redirects unauthenticated users to `/`
- Typed error handling with `PasswordlessDbChallengeError` / `PasswordlessDbGetTokenError`

## Prerequisites

- Node.js 20+
- `pnpm`
- An [Auth0 account](https://auth0.com/signup)
- EA feature flags enabled on your tenant (see Auth0 Dashboard Setup below)

## Auth0 Dashboard Setup

### 1. Enable feature flags

This feature is currently in **Early Access (EA)**. Contact your Auth0 account team to have the required feature flags enabled on your tenant.

### 2. Create an application

1. Go to **Applications → Create Application**.
2. Choose **Regular Web Application**.
3. Under **Settings**, add:
   - **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
   - **Allowed Web Origins**: `http://localhost:3000`
4. Save and note the **Domain**, **Client ID**, and **Client Secret**.

### 3. Enable OTP on your database connection

**Enable Connection Attributes**

1. Go to **Authentication → Database** and select your connection (e.g. `Username-Password-Authentication`).
2. Select the **Attributes** section.
3. Click **Add attribute** and create attributes for **email** and/or **phone**.
4. Click **Configure** on each created attribute.
5. Enable the **Use as Identifier** option.
6. Check **Allow signup** if you want new users to be able to sign up via OTP.

**Enable Connection Authentication Methods**

1. Still on your connection, select the **Authentication Methods** section.
2. Click **Configure** against the **Email** or **Phone** option.
3. Under **OTP for login**, select **Allow**.
4. Save changes.

For phone OTP, attach an SMS provider under **Branding → Phone Provider**.

### 4. Enable the connection for your application

Go to **Applications → your app → Connections** and confirm your database connection is enabled.

> [!NOTE]
> Phone OTP signup is not supported in non-interactive flows — Auth0 requires `phone_verified: true` before account creation. For phone OTP testing, pre-create the user in **User Management → Users** and mark `phone_verified: true` via the Management API. Email OTP supports signup (`allowSignup: true`) out of the box.

## Configuration

Create a `.env.local` file in this directory:

```bash
# Auth0 tenant domain — e.g. your-tenant.us.auth0.com
AUTH0_DOMAIN=

# Application credentials (from Auth0 Dashboard → Applications → your app → Settings)
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=

# Session encryption key — any random string of at least 32 characters
# Generate one with: openssl rand -hex 32
AUTH0_SECRET=

# Base URL of this app
APP_BASE_URL=http://localhost:3000

# The exact name of your database connection as it appears in Auth0 Dashboard
# Defaults to "Username-Password-Authentication" if not set
NEXT_PUBLIC_AUTH0_DB_CONNECTION=Username-Password-Authentication
```

## Running Locally

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). Select **Email** or **Phone**, enter your identifier, click **Send code**, enter the OTP you receive, and you will be redirected to `/dashboard`.

## How It Works

All auth routes are handled by `proxy.ts` — a Next.js middleware that passes every request through `auth0.middleware()`. The SDK intercepts the relevant paths internally:

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/auth/passwordless/otp/challenge` | Posts to Auth0's `/otp/challenge`, returns an opaque `authSession` |
| `POST` | `/auth/passwordless/otp/token` | Exchanges `authSession` + OTP for tokens, sets the session cookie |

The `<PasswordlessDbForm />` client component drives the flow using the `passwordless` singleton from `@auth0/nextjs-auth0/client`:

```tsx
import { passwordless } from "@auth0/nextjs-auth0/client";

// Step 1 — request OTP
const { authSession } = await passwordless.challengeWithEmail({
  email: "user@example.com",
  connection: "Username-Password-Authentication",
  allowSignup: true,
});

// Step 2 — verify OTP (session cookie set automatically on success)
await passwordless.loginWithOtp({ authSession, otp: "123456" });
```

The `authSession` returned by the challenge step is an opaque value — it is held in React state for the duration of the OTP entry step and never persisted or logged.

The challenge endpoint always returns 200 regardless of whether the user exists (user-enumeration prevention). If `allowSignup` is `false` for a non-existent user, or the user is blocked, no OTP is delivered — the `authSession` is silently non-functional. Calling `loginWithOtp` with it will fail with `invalid_request`.

Session protection on `/dashboard` is handled by `auth0.getSession()` in the Server Component — if no session exists it redirects to `/`. The `proxy.ts` middleware keeps the session rolling on every request.

## MFA

When a user has MFA configured on their account, `loginWithOtp` throws a raw `mfa_required` error. The form handles this by calling `mfa.getAuthenticators()` to determine the next step:

- **No active authenticator** — the user is guided through TOTP enrollment: a QR code is displayed (using a `<canvas>` rendered by the `qrcode` library), and after scanning, they confirm with a 6-digit code.
- **Active authenticator** — the user is prompted for their current TOTP or OOB code.

`mfa.verify()` completes authentication in both cases.

## Project Structure

```text
├── app/
│   ├── dashboard/
│   │   └── page.tsx                     ← Protected page — shows user profile and session info
│   ├── layout.tsx                        ← Root layout with Tailwind
│   └── page.tsx                          ← Home page with the passwordless DB form
├── components/
│   ├── passwordless-db-form.tsx          ← Email/phone toggle, OTP entry, full MFA flow
│   └── qr-code.tsx                       ← Canvas-based QR code for TOTP enrollment
├── lib/
│   └── auth0.ts                          ← Auth0Client singleton
└── proxy.ts                              ← Next.js middleware — passes all requests through auth0.middleware()
```
