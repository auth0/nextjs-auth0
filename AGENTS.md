# AGENTS.md

**SDK:** `@auth0/nextjs-auth0`  
**Purpose:** Auth0 authentication for Next.js (App Router + Pages Router)  
**Runtime:** Node 20+, ESM, TypeScript

---

## Quick Commands

| Task | Command |
|------|---------|
| Install | `pnpm install` |
| Build | `pnpm run build` |
| Test unit | `pnpm test:unit` |
| Test e2e | `pnpm test:e2e` |
| Lint + typecheck | `pnpm run lint` |
| Generate docs | `pnpm run docs` |

---

## Package Exports

| Import Path | Contents |
|-------------|----------|
| `@auth0/nextjs-auth0` | Client: `useUser`, `getAccessToken`, `Auth0Provider`, `withPageAuthRequired` |
| `@auth0/nextjs-auth0/server` | Server: `Auth0Client`, `AbstractSessionStore`, `TransactionStore` |
| `@auth0/nextjs-auth0/errors` | Error classes: `SdkError`, `AccessTokenError`, `AuthorizationError`, etc. |
| `@auth0/nextjs-auth0/types` | TypeScript types only: `SessionData`, `User`, `TokenSet` |
| `@auth0/nextjs-auth0/testing` | Test utilities: `generateSessionCookie` |

---

## Architecture

```
src/
├── client/           # React hooks, Auth0Provider, client getAccessToken
│   ├── hooks/        # useUser
│   ├── helpers/      # getAccessToken, withPageAuthRequired
│   └── providers/    # Auth0Provider
├── server/           # Auth0Client (public API), AuthClient (internal)
│   ├── session/      # Stateless (cookie) + Stateful (external store)
│   ├── helpers/      # withPageAuthRequired, withApiAuthRequired
│   ├── client.ts     # Auth0Client - main public class
│   └── auth-client.ts # Internal route handling + OAuth flows
├── errors/           # SdkError hierarchy (catch by error.code)
├── types/            # SessionData, User, TokenSet, AuthorizationParameters
├── utils/            # Internal: dpop, paths, scopes, urls
└── testing/          # generateSessionCookie for test session setup
```

---

## Data Flows

Legend: `→` flow, `↔` bidirectional, `[]` storage, `{}` transform

| Flow | Path |
|------|------|
| Login | Browser→`/auth/login`→Auth0`/authorize`→`/auth/callback`→{tokenSet}→[session cookie]→redirect |
| Logout | Browser→`/auth/logout`→[clear session]→Auth0`/oidc/logout`→redirect |
| getSession | [cookie]→{decrypt}→SessionData |
| getAccessToken | [session]→?expired→Auth0`/oauth/token`→{refresh}→[session update]→token |
| getAccessToken (client) | Browser→`/auth/access-token`→[session]→token |
| useUser | Browser→`/auth/profile`→[session]→User |
| Stateful session | [cookie:sid]↔[external store:SessionData] |

See [EXAMPLES.md](EXAMPLES.md) for detailed flow implementations.

---

## Key Patterns

### Public API Surface

| Class/Function | Location | Purpose |
|----------------|----------|---------|
| `Auth0Client` | `./server` | Main SDK entry, instantiate once per app |
| `useUser()` | `./client` | React hook for authenticated user |
| `getAccessToken()` | `./client` | Client-side token retrieval |
| `Auth0Provider` | `./client` | Context provider wrapping app |
| `withPageAuthRequired` | `./client` or `./server` | Page protection HOC |

### Session Storage

| Mode | Implementation | When |
|------|----------------|------|
| Stateless (default) | Encrypted cookie | No external deps |
| Stateful | Custom `SessionDataStore` | Large sessions, server-side revocation |

### Multi-Resource Refresh Tokens (MRRT)

- Multiple access tokens stored per audience in `session.accessTokens[]`
- Automatic token refresh per audience

### DPoP (Demonstrating Proof-of-Possession)

- Optional, requires `dpop.enabled: true` + key pair config
- Tokens bound to cryptographic proof

### Hooks

| Hook | Trigger |
|------|---------|
| `beforeSessionSaved` | Before session persisted, modify session data |
| `onCallback` | After OAuth callback, customize redirect/session |

---

## Error Handling

Base class: `SdkError` with `code: string` property.

| Error Class | Code | Cause |
|-------------|------|-------|
| `AccessTokenError` | `access_token_error` | Token fetch/refresh failure |
| `AuthorizationError` | `authorization_error` | OAuth authorize failure |
| `InvalidConfigurationError` | `invalid_configuration` | Bad SDK config |
| `DiscoveryError` | `discovery_error` | OIDC discovery failed |
| `OAuth2Error` | varies | Auth0 callback error (may contain user input) |

**Pattern:** Catch by `error.code`, not `instanceof`.

---

## Environment Variables

### Required

| Variable | Purpose |
|----------|---------|
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Application client ID |
| `AUTH0_CLIENT_SECRET` | Application client secret |
| `AUTH0_SECRET` | Session encryption key (min 32 chars) |
| `APP_BASE_URL` | Application base URL |

### Optional

| Variable | Purpose |
|----------|---------|
| `AUTH0_COOKIE_*` | Cookie configuration overrides |
| `AUTH0_DPOP_*` | DPoP configuration |
| `NEXT_PUBLIC_*_ROUTE` | Custom route paths |

---

## Testing

### Unit Tests

- Framework: Vitest, co-located `*.test.ts` in `src/`
- Run: `pnpm test:unit`

### Flow Tests (`*.flow.test.ts`)

Black-box tests. MSW mocks HTTP only, SDK called normally. No other mocks unless required.

---

## CI/Validation Pipeline

```bash
pnpm run test:coverage && pnpm run prepack && pnpm run lint:fix
```

E2E runs separately, requires credentials.

---

## Peer Dependencies

| Package | Versions |
|---------|----------|
| `next` | ^14.2.35 \|\| ~15.x \|\| ^16.0.10 |
| `react` | ^18.0.0 \|\| ~19.x |
| `react-dom` | ^18.0.0 \|\| ~19.x |

---

## File Conventions

| Pattern | Purpose |
|---------|---------|
| `*.test.ts` | Unit test, co-located with source |
| `*.flow.test.ts` | Integration/flow tests |
| `*.msw.test.ts` | Tests using MSW mocking |

---

## Key Files

| File | Purpose |
|------|---------|
| [src/server/client.ts](src/server/client.ts) | `Auth0Client` implementation |
| [src/server/auth-client.ts](src/server/auth-client.ts) | Internal OAuth/route handling |
| [src/client/hooks/use-user.ts](src/client/hooks/use-user.ts) | `useUser` hook |
| [src/errors/index.ts](src/errors/index.ts) | All error class definitions |
| [EXAMPLES.md](EXAMPLES.md) | Usage patterns and code samples |

---

## Anti-Patterns

- ❌ Importing from internal paths (`src/server/auth-client.ts`)
- ❌ Using `instanceof` for error handling (use `error.code`)
- ❌ Storing sensitive data in client-accessible session fields
- ❌ Calling `getAccessToken()` without checking user authentication first
