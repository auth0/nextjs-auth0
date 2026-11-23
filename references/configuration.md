# Configuration and Environment

## Required environment variables

| Variable | Purpose |
|----------|---------|
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Application client ID |
| `AUTH0_CLIENT_SECRET` | Application client secret |
| `AUTH0_SECRET` | Session encryption key (min 32 chars) |
| `APP_BASE_URL` | Application base URL |

## Optional environment variables

| Variable | Purpose |
|----------|---------|
| `AUTH0_COOKIE_*` | Cookie configuration overrides |
| `AUTH0_DPOP_*` | DPoP configuration |
| `NEXT_PUBLIC_*_ROUTE` | Custom route paths |

Never put real values in committed files; use `.env.local` (git-ignored).

## Peer dependencies (see `package.json` for exact ranges)

| Package | Versions |
|---------|----------|
| `next` | ^14.2.35 \|\| ~15.x \|\| ^16.0.10 |
| `react` | ^18.0.0 \|\| ~19.x |
| `react-dom` | ^18.0.0 \|\| ~19.x |
