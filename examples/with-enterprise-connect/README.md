# with-enterprise-connect

A Next.js App Router example demonstrating Enterprise Connect (B2B Integration) using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Shows the app-embedded integration pattern: the SaaS app owns its own login UI and session, while Auth0 handles only the enterprise SSO federation.

## What this example covers

- Home Realm Discovery via `startEnterpriseLogin`: detect whether a user's email domain is federated and, if so, redirect to Auth0 with the email as `login_hint`. Auth0 resolves the connection and organization from the domain.
- Stateless passthrough: Auth0 completes the SSO handshake but writes no session cookie.
- Cookie-based own-session pattern: the app writes its own `app_session` cookie in `onCallback`.
- EC-aware logout: federated logout terminates the enterprise IdP session.

## Prerequisites

- Node.js 20+
- `pnpm`
- An [Auth0 account](https://auth0.com/signup) with Enterprise Connect enabled on your tenant

## Auth0 Setup

### 1. Create a B2B Integration client

1. Go to **Applications → B2B Integrations → + Enterprise Connect Integration**.
2. Enter an **Integration Name** (e.g. `Acme Auth0 Integration`).
3. Under **Integration Type**, select **Application**.
4. Click **Save And Continue**, then close the wizard.
5. Go to the **Settings** tab and add:
   - **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000/login`
6. Note the **Client ID** and **Client Secret**.

### 2. Onboard an enterprise customer

1. Go to the **Organizations** tab and click **Set Up Customer Onboarding** to create an SSO Profile and UAP (first time only).
2. Click **Create Organization**, enter a name and display name, and proceed to the ticket configuration step.
3. Enter a **Connection Name**, set **Identity Provider Domains** to the customer's email domain, enable **Assign membership on login**, select your B2B Integration client under **Enabled Clients**, and click **Generate Ticket**.
4. Open the ticket URL and complete the self-service wizard as the enterprise customer's IT admin to configure their IdP.

After the wizard completes, verify `assign_membership_on_login` is `true` on the connection:

```bash
curl -X PATCH "https://<your-tenant>/api/v2/organizations/<org_id>/enabled_connections/<connection_id>" \
  -H "Authorization: Bearer <mgmt_token>" \
  -H "Content-Type: application/json" \
  -d '{ "assign_membership_on_login": true }'
```

## Configuration

Create `.env.local` in this directory:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=          # from the B2B Integration client, not a regular app
AUTH0_CLIENT_SECRET=      # from the B2B Integration client
AUTH0_SECRET=             # openssl rand -hex 32
APP_BASE_URL=http://localhost:3000
```

## Running Locally

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). Enter a federated email to trigger enterprise SSO, or a non-federated email to see the non-enterprise path.

## How It Works

### Login

The app offers two variants of the same flow:

- **Form POST (`app/login/page.tsx` → `app/api/login/route.ts`)**: the browser POSTs the email to a Route Handler, which calls `auth0.startEnterpriseLogin({ email, returnTo })`. This must be a Route Handler, not a Server Action: `startEnterpriseLogin` returns a `NextResponse` carrying the transaction (`__txn_*`) cookie that has to reach `/auth/callback`, and only a Route Handler returns that response to the browser. The handler re-emits the SDK's `307` redirect as `303` so the browser switches the POST to a GET for Auth0's `/authorize` endpoint.
- **Client component (`app/login/client/page.tsx`)**: uses the browser-side `startEnterpriseLogin` helper, which calls the SDK's mounted `/auth/federated-domain` and `/auth/login` routes over HTTP. Use this when you want loading/error state without a full page reload.

Either way, `startEnterpriseLogin` runs domain discovery and, for a federated domain, redirects to Auth0 with the email as `login_hint`. For a non-federated domain it hands control back so you can route to your own login.

### Callback

`onCallback` in `lib/auth0.ts` receives the ID token claims in `session.user`. It reads `org_id`, writes an `app_session` cookie, and returns a `NextResponse` redirect to `/dashboard`. Auth0 writes no session cookie, so `auth0.getSession()` is unavailable in this mode.

### Session

`getAppSession()` in `lib/auth0.ts` reads the `app_session` cookie directly. The dashboard and other protected pages use this rather than `auth0.getSession()`.

### Logout

`GET /api/logout` clears the `app_session` cookie and delegates to `/auth/logout?federated=true`. The SDK builds the `/oidc/logout` URL and forwards `federated`, terminating the enterprise IdP session. `returnTo` becomes the OIDC `post_logout_redirect_uri`, which Auth0 requires to be an absolute URL registered as an Allowed Logout URL.

## Project Structure

```text
├── app/
│   ├── api/
│   │   ├── login/route.ts          ← form POST entry point, calls startEnterpriseLogin
│   │   └── logout/route.ts         ← clear own session, delegate to SDK logout
│   ├── dashboard/page.tsx          ← protected page, reads app_session
│   ├── login/
│   │   ├── page.tsx                ← form POST login variant
│   │   └── client/page.tsx         ← client-side startEnterpriseLogin variant
│   └── page.tsx                    ← redirects to /dashboard or /login
├── lib/
│   └── auth0.ts                    ← Auth0Client + onCallback + getAppSession
└── proxy.ts                        ← Next.js middleware (Next.js 16)
```
