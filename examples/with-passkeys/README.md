# with-passkeys

A Next.js App Router example demonstrating passkey (WebAuthn) authentication using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Users sign in with device biometrics or a PIN — the private key never leaves their device's secure enclave.

## What this example covers

- **Passkey signup** — new user registers a passkey tied to their device
- **Passkey login** — returning user authenticates with a stored passkey
- **Passkey enrollment** — authenticated user adds an additional passkey from the dashboard
- **Step-by-step signup** (via Server Actions) — advanced example with full control over each WebAuthn step
- **Universal Login fallback** — redirect to Auth0's hosted login page
- Protected `/dashboard` route that redirects unauthenticated users to `/`
- Typed error handling with `PasskeyRegisterError`, `PasskeyChallengeError`, `PasskeyGetTokenError`, `PasskeyEnrollmentChallengeError`, `PasskeyEnrollmentVerifyError`

## Prerequisites

- Node.js 20+
- `pnpm`
- An [Auth0 account](https://auth0.com/signup)
- Passkeys enabled on your Auth0 tenant

## Auth0 Dashboard Setup

### 1. Create an application

1. Go to **Applications → Create Application**.
2. Choose **Regular Web Application**.
3. Under **Settings**, add the following:
   - **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
   - **Allowed Web Origins**: `http://localhost:3000`
4. Save changes and note down the **Domain**, **Client ID**, and **Client Secret**.

### 2. Enable passkeys

Passkeys use WebAuthn, which ties credentials to an `rpId` (relying party ID) matching your app's origin.

- For local development, the `rpId` is `localhost`.
- For production, configure a **Custom Domain** under **Branding → Custom Domains** — the passkey `rpId` will be your custom domain.

> **Note:** The required signup identifier (email, username, or phone) depends on your database connection's **Attributes** configuration. Ensure the field you pass during signup matches the identifier type configured on your connection.

### 3. Enable passkey enrollment (MyAccount API)

The enrollment flow uses the Auth0 MyAccount API. To enable it:

1. Configure a **Multi-Resource Refresh Token (MRRT)** policy for your application with audience `https://{your-domain}/me/` and scope `create:me:authentication_methods`.
2. Ensure `create:me:authentication_methods` is included in your application's allowed scopes.

The SDK exchanges the session's refresh token for a MyAccount-scoped access token automatically at enrollment time via MRRT.

## Configuration

Create a `.env.local` file in this directory:

```bash
cp .env.local.example .env.local
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

Open [http://localhost:3000](http://localhost:3000). Choose **Sign up** to register a new passkey or **Sign in** to authenticate with an existing one. After a successful ceremony you are redirected to `/dashboard` where you can also enroll additional passkeys.

> **Note:** Passkeys require HTTPS in production. For local testing, `localhost` is treated as a secure origin by browsers and works without TLS.

## How It Works

All auth routes are handled by `proxy.ts` — a Next.js middleware that passes every request through `auth0.middleware()`. The SDK intercepts the relevant paths internally:

| Method | Path | What it does |
|--------|------|--------------|
| `POST` | `/auth/passkey/register` | Calls Auth0 `POST /passkey/register` and returns the WebAuthn creation options |
| `POST` | `/auth/passkey/challenge` | Calls Auth0 `POST /passkey/challenge` and returns the WebAuthn request options |
| `POST` | `/auth/passkey/get-token` | Exchanges the signed WebAuthn credential for tokens via `POST /oauth/token` and sets the session cookie |
| `POST` | `/auth/passkey/enrollment-challenge` | Calls Auth0 MyAccount `POST /me/v1/authentication-methods` — requires an active session |
| `POST` | `/auth/passkey/enrollment-verify` | Calls Auth0 MyAccount `POST /me/v1/authentication-methods/{id}/verify` — completes enrollment |

The `<PasskeyForm />` client component drives signup and login using the `passkey` singleton from `@auth0/nextjs-auth0/client`. The `<PasskeyEnrollForm />` component on `/dashboard` drives enrollment for authenticated users by calling the enrollment routes directly via `fetch`.

```tsx
import { passkey } from "@auth0/nextjs-auth0/client";

// New user — signup (fetches challenge, calls navigator.credentials.create, verifies)
await passkey.signup({ email: "user@example.com", name: "Jane" });

// Returning user — login (fetches challenge, calls navigator.credentials.get, verifies)
await passkey.login();
```

All `ArrayBuffer ↔ base64url` conversion required by the WebAuthn API is handled internally by the SDK. Session protection on `/dashboard` is handled by `auth0.getSession()` in the Server Component — if no session exists it redirects to `/`.

## Universal Login

Auth0's Universal Login is the **simplest and most secure approach**. Instead of your app owning the WebAuthn form, you redirect to `/auth/login` and Auth0 handles everything on a hosted page:

```tsx
<a href="/auth/login">Continue with Universal Login</a>
```

Auth0 redirects back to `/auth/callback` after authentication, and the SDK creates a session exactly like a standard login. The example includes this as a fallback option below the passkey form.

| | Universal Login | Custom Login (headless) |
|---|---|---|
| **UI** | Auth0-hosted | Your own components |
| **Code required** | One link | Form + WebAuthn ceremony |
| **Security** | Credentials stay with Auth0 | Private key never leaves device |
| **Customisation** | Auth0 Dashboard branding | Complete |
| **Recommended** | ✅ Default | Advanced / full UI control |

## Project Structure

```text
├── app/
│   ├── actions/
│   │   └── passkey.ts              ← Server Actions for the step-by-step signup flow
│   ├── dashboard/
│   │   └── page.tsx                ← Protected page — shows user profile + enroll form
│   ├── signup-advanced/
│   │   └── page.tsx                ← Step-by-step signup using Server Actions
│   ├── layout.tsx                  ← Root layout
│   └── page.tsx                    ← Home page with the passkey form
├── components/
│   ├── passkey-form.tsx            ← Sign up / Sign in UI using the passkey singleton
│   ├── passkey-advanced-form.tsx   ← Step-by-step signup form using Server Actions
│   └── passkey-enroll-form.tsx     ← Enroll an additional passkey for authenticated users
├── lib/
│   └── auth0.ts                    ← Auth0Client singleton
└── proxy.ts                        ← Next.js middleware — passes all requests through auth0.middleware()
```
