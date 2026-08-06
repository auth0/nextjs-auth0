# with-myorg

This example demonstrates how to integrate Auth0's **My Organization API** into a Next.js application using `@auth0/nextjs-auth0`.

It shows two key capabilities side by side:

1. **BFF proxy** — the SDK's built-in middleware intercepts all `/my-org/*` requests from the browser, attaches a server-side access token, and forwards them to the Auth0 My Organization API. No token is ever exposed to the browser.

2. **Permission-based UI gating** — Auth0 returns a `urn:auth0:my_org_current_user_permissions` claim in the ID token. The SDK passes it through to `session.user` automatically. The server component reads it via `auth0.getSession()` and passes it as props — no extra API call needed.

## Prerequisites

- An Auth0 tenant with the **My Organization API** enabled
- MRRT (Multi-Resource Refresh Token) enabled on your application so the SDK can obtain a separate token for the `https://<domain>/my-org/` audience
- The `urn:auth0:my_org_current_user_permissions` claim enabled in your Auth0 tenant (available automatically once My Org is enabled)

## Setup

1. Copy `.env.example` to `.env.local` and fill in your values:

```bash
cp .env.example .env.local
```

| Variable | Description |
|---|---|
| `AUTH0_DOMAIN` | Your Auth0 tenant domain, e.g. `tenant.auth0.com` |
| `AUTH0_CLIENT_ID` | Your application's Client ID |
| `AUTH0_CLIENT_SECRET` | Your application's Client Secret |
| `AUTH0_SECRET` | A long random string used to encrypt the session cookie |
| `APP_BASE_URL` | The base URL of your app, e.g. `http://localhost:3000` |

2. Install dependencies and run:

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

## How it works

### Auth0 client (`lib/auth0.ts`)

```ts
new Auth0Client({
  authorizationParameters: {
    organization: process.env.AUTH0_ORGANIZATION_ID,
    audience: process.env.AUTH0_AUDIENCE,
    scope: "openid profile email offline_access read:my_org:configuration read:my_org:members read:my_org:member_roles create:my_org:member_invitations create:my_org:member_roles delete:my_org:member_roles"
  }
});
```

### Proxy (`proxy.ts`)

```ts
export async function proxy(request: NextRequest) {
  return await auth0.middleware(request);
}
```

That single line is all that's needed. The SDK automatically:
- Handles `/auth/login`, `/auth/logout`, `/auth/callback`
- Intercepts any browser request to `/my-org/*`, fetches a scoped access token server-side, and proxies the request to `https://<domain>/my-org/`

### Organization dashboard (`components/org-dashboard.tsx`)

A Client Component that:
- Receives `permissions` as a prop from the server component, which reads them via `auth0.getSession()`
- Gates the **Invite Member** button on `create:my_org:member_invitations`
- Gates the **Roles** button per member on `create:my_org:member_roles`
- Calls `/my-org/v1/config` and `/my-org/v1/members` through the BFF proxy

### Home page (`app/page.tsx`)

A Server Component that calls `auth0.getSession()`, reads `urn:auth0:my_org_current_user_permissions` from `session.user`, and passes it as a `permissions` prop to `OrgDashboard`.
