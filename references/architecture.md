# Architecture, Data Flows and Key Patterns

Detail carried forward from the previous `AGENTS.md`. Summary and pointers live in [CLAUDE.md](../CLAUDE.md).

## Package Exports

| Import Path | Contents |
|-------------|----------|
| `@auth0/nextjs-auth0` | Client: `useUser`, `getAccessToken`, `Auth0Provider`, `withPageAuthRequired` |
| `@auth0/nextjs-auth0/server` | Server: `Auth0Client`, `AbstractSessionStore`, `TransactionStore` |
| `@auth0/nextjs-auth0/errors` | Error classes: `SdkError`, `AccessTokenError`, `AuthorizationError`, etc. |
| `@auth0/nextjs-auth0/types` | TypeScript types only: `SessionData`, `User`, `TokenSet` |
| `@auth0/nextjs-auth0/testing` | Test utilities: `generateSessionCookie` |

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

## Data Flows

Legend: `→` flow, `↔` bidirectional, `[]` storage, `{}` transform

| Flow | Path |
|------|------|
| Login | Browser→`/auth/login`→Auth0`/authorize`→`/auth/callback`→{tokenSet}→[session cookie]→redirect |
| Logout | Browser→`/auth/logout`→[clear session]→Auth0`/oidc/logout`→redirect |
| getSession | [cookie]→{decrypt}→SessionData |
| getAccessToken | [session]→?expired→Auth0`/oauth/token`→{refresh}→[session update]→token (session update does not persist in Server Components, see note) |
| getAccessToken (client) | Browser→`/auth/access-token`→[session]→token |
| useUser | Browser→`/auth/profile`→[session]→User |
| Stateful session | [cookie:sid]↔[external store:SessionData] |

Server Components cannot set cookies: `getAccessToken()` there refreshes an expired token but the refreshed token set is not persisted. To persist it, call `getAccessToken(req, res)` in middleware.

See [EXAMPLES.md](../EXAMPLES.md) for detailed flow implementations.

## Public API Surface

| Class/Function | Location | Purpose |
|----------------|----------|---------|
| `Auth0Client` | `./server` | Main SDK entry, instantiate once per app |
| `useUser()` | `./client` | React hook for authenticated user |
| `getAccessToken()` | `./client` | Client-side token retrieval |
| `Auth0Provider` | `./client` | Context provider wrapping app |
| `withPageAuthRequired` | `./client` (standalone); server: `auth0.withPageAuthRequired(...)` on the `Auth0Client` instance | Page protection HOC |

## Session Storage

| Mode | Implementation | When |
|------|----------------|------|
| Stateless (default) | Encrypted cookie | No external deps |
| Stateful | Custom `SessionDataStore` | Large sessions, server-side revocation |

## Multi-Resource Refresh Tokens (MRRT)

- Multiple access tokens stored per audience in `session.accessTokens[]`
- Automatic token refresh per audience

## DPoP (Demonstrating Proof-of-Possession)

- Optional, requires `useDPoP: true` plus `dpopKeyPair` (or the DPoP key environment variables)
- Tokens bound to cryptographic proof

## Hooks

| Hook | Trigger |
|------|---------|
| `beforeSessionSaved` | Before session persisted, modify session data |
| `onCallback` | After OAuth callback, customize redirect/session |

## Key Files

| File | Purpose |
|------|---------|
| [src/server/client.ts](../src/server/client.ts) | `Auth0Client` implementation |
| [src/server/auth-client.ts](../src/server/auth-client.ts) | Internal OAuth/route handling |
| [src/client/hooks/use-user.ts](../src/client/hooks/use-user.ts) | `useUser` hook |
| [src/errors/index.ts](../src/errors/index.ts) | All error class definitions |
| [EXAMPLES.md](../EXAMPLES.md) | Usage patterns and code samples |
