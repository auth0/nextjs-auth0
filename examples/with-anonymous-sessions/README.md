# Anonymous Sessions Example

This example demonstrates anonymous sessions (EA feature) in @auth0/nextjs-auth0.

## Features

- **Create Anonymous Sessions**: Generate anonymous identity before login with optional metadata
- **SSR Seed**: Server-side anonymous session fetch prevents loading flash
- **Login-to-Link**: Convert anonymous session to authenticated account
- **Protected API**: Use anonymous access token to call audience-protected resources
- **Client Hook**: `useAnonymousSession()` for live session state
- **Security Best Practices**: SEC-1 (the session token never reaches `/authorize`), metadata set-once

## Prerequisites

1. **Build SDK First**: Run `pnpm build` at the repository root to compile the SDK (required for `file:../..` dependency)
2. **Tenant Configuration**: anonymous sessions are an early-access feature, so the tenant needs:
   - `oidc_conformant: true` on client
   - `anonymous_sessions.active: true` on client
   - Client grant with `subject_type: anonymous_user` for audience `https://api.customers`
3. **Environment Variables**: Copy `.env.example` to `.env.local` and fill in your Auth0 tenant credentials

## Setup

```bash
# 1. Install dependencies (from example directory)
pnpm install

# 2. Configure .env.local
cp .env.example .env.local
# Edit .env.local with your Auth0 tenant credentials

# 3. Run development server
pnpm dev
```

Visit http://localhost:3000

## Demo Flow

1. **Home Page** (`/`):
   - "Enter as Guest" → creates an anonymous session by POSTing to `/api/anon/create`
   - "Create with Metadata" → creates session with custom metadata (e.g., cart state)
   - Fail-loud diagnostic if tenant misconfigured (403 unauthorized_client)

2. **Demo Page** (`/demo`):
   - SSR session display (may be stale, D7)
   - Client-side live session panel (`useAnonymousSession()`)
   - Logout and Refresh buttons (Refresh revalidates `GET /auth/anonymous-session`, which renews an expired access token)
   - "Login to Link" → converts anonymous session to authenticated account (SEC-1: the SDK sends a transfer ticket minted from its cookie, no param)
   - "Fetch Products" → calls protected API with anonymous access token

## API Routes

- `GET /auth/anonymous-session` — SDK route: returns the current anonymous session (200 JSON) or 204 when there is none; it never creates one, and renews an expired access token
- `POST /auth/anonymous-session/logout` — SDK route: clears cookie (no server-side revocation)
- `POST /api/anon/create` — App route: creates session with metadata
- `GET /api/products` — App route: uses access token to call protected API (stub)

## Security Notes

- **SEC-1 (Session Token Fixation)**: at login the SDK exchanges the session token from its own cookie for a short-lived transfer ticket and sends it as `anon_transfer_token`; a `session_token` or `anon_transfer_token` passed by the caller is dropped, and the callback re-checks the cookie before reporting the link.
- **Metadata Set-Once**: Metadata can only be set at creation time, cannot be updated after (CASCADE-v2 M2).
- **No Server Revocation**: Logout clears the client cookie but does NOT revoke the session server-side; tokens remain valid until expiry.
- **SSR Staleness (D7)**: Server Component `getAnonymousSession()` reads may be stale; renewal is deferred to route handlers.

## Scripts

- `pnpm dev` — Start development server
- `pnpm build` — Build for production
- `pnpm start` — Run production build
- `pnpm lint` — Run ESLint
- `pnpm test` — Unit + MSW tests (Vitest)
- `pnpm test:e2e:l9` — SEC-1 session_token-strip browser test (Playwright, creds-free)
- `pnpm test:e2e` — All Playwright specs

## Testing

Unit/integration (Vitest): `pnpm test`. Deterministic MSW-backed and live-tenant
tiers; the live server tier skips without tenant creds.

Browser (Playwright, `tests/e2e/`):

> **Note:** These browser tests use an example-local Playwright harness. When the repo-wide e2e suite (`feat/e2e-test-suite`, root `e2e/`) lands in main, this coverage will fold into that centralized harness and adopt its shared login helper (`loginWithAuth0`) and `injectSession` conventions.

**Offline Mock Tier**

The offline tier tests the example wiring and SDK logic against a mock Auth0 tenant. The mock (injected via `customFetch` at `lib/mock/anon-mock-fetch.ts`) intercepts `POST /anonymous/token` and `POST /anonymous/logout` requests and returns configurable responses (success, expired, 403/400/500 errors). The SDK's real encrypt/persist/decrypt/renew logic executes normally. No tenant credentials required.

Run: `pnpm test:e2e:offline`. Runs 17 specs covering session lifecycle (create, get, renew, logout), error paths (feature_not_enabled, unauthorized_client, invalid_target, invalid_scope, server_error, metadata_too_large), and UI states (loading, error banner, metadata display).

**Live Tier**

- **L9 — SEC-1 strip** (`sec1-strip.spec.ts`): proves a caller-supplied
  `session_token` on `/auth/login` never reaches `/authorize`, and that a
  cookie-derived `anon_transfer_token` is sent instead. L9a/L9c are
  creds-free (CI-safe); L9b mints a real `auth0_anon` cookie and needs
  `.env.local`. Run: `pnpm test:e2e:l9`.
- **L10 — callback link** (`link-callback.spec.ts`): drives a real Universal
  Login and asserts the callback links the anonymous session (`?linked=true`
  banner). Gated; skips unless a tenant test user is supplied:

  ```bash
  TEST_USER_EMAIL=you@example.com TEST_USER_PASSWORD=... \
    pnpm exec playwright test link-callback
  ```

  First run installs the browser: `pnpm exec playwright install chromium`.

## Production Checklist

This example includes test-only files for the offline e2e harness. Before deploying to production or using this example as a template for a real application, remove the following directories and files:

- `lib/mock/` — offline mock fetch for E2E_ANON_MOCK mode
- `app/api/test/` — scenario injection route for test harness
- `playwright.offline.config.ts` and `tests/e2e/offline/`
- The `E2E_ANON_MOCK` gated `customFetch` line in `lib/auth0.ts`

These files exist solely to support offline testing without Auth0 tenant credentials. They have no role in a production application and should never be deployed to dev, staging, or production environments.

## Dependencies

- `@auth0/nextjs-auth0`: `file:../..` (local SDK build)
- `next`: 16.3.3
- `react`: 19.2.1

## Notes

- Next.js 16 calls the request interceptor `proxy.ts` (`middleware.ts` is deprecated); this example mounts the SDK there.
