# Passwordless Authentication Example

This example demonstrates passwordless authentication (email OTP and SMS OTP) using `@auth0/nextjs-auth0`.

## What it shows

- **Email OTP** — user enters their email, receives a one-time code, verifies it to sign in
- **SMS OTP** — same flow using a phone number
- Built-in route handlers served via `auth0.handler` (no manual route boilerplate)
- Client-side `passwordless` singleton from `@auth0/nextjs-auth0/client`
- Typed error handling with `PasswordlessStartError` / `PasswordlessVerifyError`
- Protected dashboard page using `auth0.getSession()`

## Auth0 Dashboard Setup

Before running the example you must configure a **Passwordless** connection:

1. Go to **Authentication → Passwordless** in the Auth0 Dashboard.
2. Enable **Email** and/or **SMS** and configure the OTP settings.
3. Go to **Applications → \<your app\>** and enable the passwordless connection under the **Connections** tab.
4. Ensure `http://localhost:3000/auth/callback` is listed in **Allowed Callback URLs**.
5. Ensure `http://localhost:3000` is listed in **Allowed Logout URLs**.

## Getting Started

1. Copy the example environment file and fill in your values:

   ```bash
   cp .env.example .env.local
   ```

   | Variable | Description |
   |---|---|
   | `AUTH0_DOMAIN` | Your Auth0 tenant domain, e.g. `dev-xxx.us.auth0.com` |
   | `AUTH0_CLIENT_ID` | Application Client ID |
   | `AUTH0_CLIENT_SECRET` | Application Client Secret |
   | `AUTH0_SECRET` | Random string ≥ 32 chars used to encrypt the session cookie |
   | `APP_BASE_URL` | Base URL of this app, default `http://localhost:3000` |

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. Start the development server:

   ```bash
   pnpm dev
   ```

4. Open [http://localhost:3000](http://localhost:3000).

## How It Works

The SDK registers two route handlers automatically through `auth0.handler`:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/passwordless/start` | Sends OTP to the user's email or phone |
| `POST` | `/auth/passwordless/verify` | Verifies OTP and creates a session cookie |

The `<PasswordlessForm />` client component calls these routes via the `passwordless` singleton:

```typescript
import { passwordless } from "@auth0/nextjs-auth0/client";

// Step 1 — send code
await passwordless.start({ connection: "email", email, send: "code" });

// Step 2 — verify code (session cookie set automatically on success)
await passwordless.verify({ connection: "email", email, verificationCode: code });
```

## Project Structure

```
├── app/
│   ├── auth/[auth0]/route.ts   ← GET + POST handler (all auth routes)
│   ├── dashboard/page.tsx      ← Protected page showing user profile
│   └── page.tsx                ← Home page with the passwordless form
├── components/
│   └── passwordless-form.tsx   ← Two-step OTP form (email + SMS)
├── lib/
│   └── auth0.ts                ← Auth0Client singleton
└── middleware.ts                ← Session refresh middleware
```
