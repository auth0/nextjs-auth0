# with-enterprise-connect

A Next.js App Router example demonstrating Enterprise Connect (B2B Integration) using [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). Shows the app-embedded integration pattern — the SaaS app owns its own login UI and session, Auth0 handles only the enterprise SSO federation.

## What this example covers

- Domain discovery via `isFederatedDomain` — detect whether a user's email domain is federated for enterprise SSO
- Stateless passthrough — Auth0 completes the SSO handshake but writes no session cookie
- Cookie-based own-session pattern — app writes its own `app_session` cookie in `onCallback`
- EC-aware logout — federated logout terminates the enterprise IdP session via SAML SLO
- Per-domain enterprise config lookup pattern (`getEnterpriseConfig`)

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
AUTH0_CLIENT_ID=          # from the B2B Integration client — not a regular app
AUTH0_CLIENT_SECRET=      # from the B2B Integration client
AUTH0_SECRET=             # openssl rand -hex 32
APP_BASE_URL=http://localhost:3000
```

## Running Locally

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). Enter a federated email (e.g. `user@zillo.com`) to trigger enterprise SSO, or a non-federated email to see the non-enterprise path.

## How It Works

### Domain discovery

`POST /api/check-domain` calls `isFederatedDomain` server-side and also calls `getEnterpriseConfig` to look up the `connection` name and `org_id` for the email domain. In production `getEnterpriseConfig` queries your database — in this example it throws with instructions to implement it.

### Login

The login form (`app/login/page.tsx`) POSTs the email to `/api/check-domain`. If federated, it redirects to `/auth/login?connection=...&organization=...`. Both `connection` and `organization` are required — omitting `organization` triggers the Auth0 org-selection prompt which rejects `connection`.

### Callback

`onCallback` in `lib/auth0.ts` receives the ID token claims in `session.user`. It validates `org_id`, writes an `app_session` cookie, and returns a `NextResponse` redirect to `/dashboard`. Auth0 writes no session cookie — `auth0.getSession()` is unavailable in this mode.

### Session

`getAppSession()` in `lib/auth0.ts` reads the `app_session` cookie directly. Dashboard and other protected pages use this rather than `auth0.getSession()`.

### Logout

`GET /api/logout` clears the `app_session` cookie and delegates to `/auth/logout?federated=true`. The SDK constructs the correct `/oidc/logout` URL with `federated=true`, terminating the enterprise IdP session via SAML SLO.

## Project Structure

```text
├── app/
│   ├── api/
│   │   ├── check-domain/route.ts   ← isFederatedDomain + getEnterpriseConfig
│   │   ├── logout/route.ts         ← clear own session, delegate to SDK logout
│   │   
│   ├── dashboard/page.tsx          ← protected page, reads app_session
│   ├── login/page.tsx              ← login form with domain check
│   └── page.tsx                    ← redirects to /dashboard or /login
├── lib/
│   └── auth0.ts                    ← Auth0Client + getAppSession + getEnterpriseConfig
└── proxy.ts                        ← Next.js middleware (Next.js 16)
```
