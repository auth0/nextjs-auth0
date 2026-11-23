# Configuration and Environment

## Required environment variables

| Variable | Purpose |
|----------|---------|
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Application client ID |
| `AUTH0_CLIENT_SECRET` | Application client secret |
| `AUTH0_SECRET` | Session encryption key: random 32-byte secret as 64 hex characters (`openssl rand -hex 32`) |
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
| `next` | ^14.2.35 \|\| ~15.0.7 \|\| ~15.1.11 \|\| ~15.2.8 \|\| ~15.3.8 \|\| ~15.4.10 \|\| ~15.5.9 \|\| ^16.0.10 |
| `react` | ^18.0.0 \|\| ~19.0.1 \|\| ~19.1.2 \|\| ^19.2.1 |
| `react-dom` | ^18.0.0 \|\| ~19.0.1 \|\| ~19.1.2 \|\| ^19.2.1 |
