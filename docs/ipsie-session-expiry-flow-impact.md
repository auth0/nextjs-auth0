# IPSIE `session_expiry` — Flow Impact Analysis

## What the feature does

1. **At login** (`handleCallback`): reads `session_expiry` Unix-seconds from the ID token, stamps it as `session.internal.sessionExpiresAt`. If the ceiling is already in the past at login time, the session is rejected immediately — nothing is persisted.
2. **On every session read** (`getSessionWithDomainCheck`): if `now >= sessionExpiresAt - 30s`, returns `{ session: null }` as if no session exists, and fires `deleteByReqCookies` to clean up stateful stores.
3. **On every token fetch** (`getTokenSet`): if ceiling reached, returns `AccessTokenError(SESSION_EXPIRED)` immediately — Auth0's token endpoint is never called.
4. **`getAccessTokenForConnection`** explicitly bypasses the ceiling via `getSessionWithoutCeilingCheck`.

The 30-second leeway is applied to absorb clock skew between the SDK server and the IdP.

---

## Full flow table

| # | Flow | Ceiling fires? | Why / Why not | Code location |
|---|---|---|---|---|
| 1 | `getSession()` — App Router | **YES** | Calls `getSessionWithDomainCheck` → returns `null` | `client.ts:856` |
| 2 | `getSession(req)` — Pages Router | **YES** | Same path with explicit req cookies | `client.ts:838` |
| 3 | `getAccessToken()` — App Router server | **YES (double)** | (a) `getSessionWithDomainCheck` → `MISSING_SESSION`; (b) `getTokenSet` pre-check → `SESSION_EXPIRED` | `client.ts:999` |
| 4 | `getAccessToken(req, res)` — Pages Router | **YES (double)** | Same as #3 | `client.ts:939` |
| 5 | `getAccessTokenForConnection()` | **NO** | Explicitly calls `getSessionWithoutCeilingCheck` — connection tokens follow the upstream IdP's own token TTLs, not the IPSIE primary session ceiling | `client.ts:1110` |
| 6 | `handleCallback` — redirect flow | **YES (at login)** | `isSessionCeilingInPast` checked before `sessionStore.set`; rejected sessions are never persisted | `auth-client.ts:1454` |
| 7 | `handleCallback` — popup flow | **YES (at login)** | Same check in popup branch; `onCallback` is now also called before the early return | `auth-client.ts:1399` |
| 8 | `handleProfile` — `/auth/profile` | **YES** | `getSessionWithDomainCheck` → returns `null` → 401 | `auth-client.ts:1513` |
| 9 | `handleAccessToken` — `/auth/access-token` | **YES (double)** | Same double-check as #3; additionally calls `sessionStore.delete` explicitly on `SESSION_EXPIRED` | `auth-client.ts:1878` |
| 10 | `middleware` — rolling session touch | **YES** | `getSessionWithDomainCheck` returns `null` → rolling `sessionStore.set` is skipped; ceiling is observed immediately | `auth-client.ts:730` |
| 11 | `withPageAuthRequired()` — App Router | **YES** | Calls `getSession()` → `null` → redirects to login | `with-page-auth-required.ts:210` |
| 12 | `withPageAuthRequired(req)` — Pages Router | **YES** | Same via `getSession(req)` | `with-page-auth-required.ts:230` |
| 13 | `withApiAuthRequired()` — App Router | **YES** | Calls `getSession()` → `null` → 401 | `with-api-auth-required.ts:81` |
| 14 | `withApiAuthRequired(req, res)` — Pages Router | **YES** | Same | `with-api-auth-required.ts:109` |
| 15 | `updateSession()` — App Router | **YES** | Reads session first → `null` → throws "user not authenticated" | `client.ts:1340` |
| 16 | `updateSession(req, res)` — Pages Router | **YES** | Same | `client.ts:1368` |
| 17 | `useUser()` — browser hook | **YES (server-side)** | Hook calls `/auth/profile` → `handleProfile` → 401 → hook reflects logged-out state | `use-user.ts:22` |
| 18 | `getAccessToken()` — browser helper | **YES (server-side)** | Calls `/auth/access-token` → `handleAccessToken` → `SESSION_EXPIRED` error thrown | `get-access-token.ts:129` |
| 19 | `connectAccount()` | **YES** | `getSessionWithDomainCheck` fires on the existing session before the connect flow proceeds | `auth-client.ts:3415` |
| 20 | `handleMyAccount()` — `/me/*` proxy | **YES** | `#handleProxy` calls `getSessionWithDomainCheck` to get the session and access token | `auth-client.ts:2155` |
| 21 | `handleMyOrg()` — `/my-org/*` proxy | **YES** | Same proxy path as #20 | `auth-client.ts:2164` |
| 22 | `mfa.getAuthenticators()` | **NO** | Uses an encrypted `mfaToken` passed in the request body — no session read at all | `auth-client.ts:3793` |
| 23 | `mfa.challenge()` | **NO** | Same — `mfaToken` from request body, no session read | `auth-client.ts:3867` |
| 24 | `mfa.verify()` / `handleVerify` | **YES (caching only)** | The token exchange with Auth0 succeeds; ceiling fires when caching the new token back onto the session | `auth-client.ts:4163` |
| 25 | `mfa.associate()` / `handleMfaAssociate` | **YES** | `getSessionWithDomainCheck` validates the current session before associating | `auth-client.ts:1663` |
| 26 | `passkey.enrollmentChallenge()` | **YES** | Enrolling a passkey requires an active session → `getSessionWithDomainCheck` | `auth-client.ts:4793` |
| 27 | `passkey.enrollmentVerify()` | **YES** | Same — active session required | `auth-client.ts:4866` |
| 28 | `passkey.register()` / `passkey.challenge()` | **NO** | Unauthenticated operations — generate a new login challenge, no existing session is read | `auth-client.ts:4207` |
| 29 | `passkey.getToken()` / `handlePasskeyGetToken` | **NO** | Creates a **new** session from a fresh token response; if the new ID token contains `session_expiry`, a new ceiling is stamped at creation | `auth-client.ts:4334` |
| 30 | `passwordless.start()` | **NO** | Unauthenticated — initiates login flow, no existing session involved | `auth-client.ts:4982` |
| 31 | `passwordless.verify()` / `handlePasswordlessVerify` | **NO** | Creates a **new** session; same reasoning as #29 | `auth-client.ts:5129` |
| 32 | `handleLogout()` | **NO** | Logout only deletes the session — it does not need to validate it. An already-expired session can still be logged out cleanly | `auth-client.ts:929` |
| 33 | `customTokenExchange()` | **NO** | Standalone token exchange with no user session involved | `auth-client.ts:3210` |
| 34 | `backchannelAuthentication()` (CIBA) | **NO** | Polling loop that creates new tokens from scratch — no existing session read | `auth-client.ts:2328` |

---

## Flows to add to the example for manual testing

The `with-ipsie-session-expiry` example currently only covers flows **#1, #3, #9, #17, #18** (getSession, getAccessToken server + client, handleAccessToken via the browser panel). The gaps that are testable without additional tenant setup:

| Flow | What to build |
|---|---|
| **#17 — `useUser()` browser hook** | `UseUserPanel` client component calling `useUser()`. After ceiling → should show `null` / logged-out state without a page redirect. |
| **#11 — `withPageAuthRequired()`** | `/protected` page wrapped with `withPageAuthRequired`. After ceiling → should auto-redirect to `/auth/login`. |
| **#13 — `withApiAuthRequired()`** | `/api/protected` route wrapped with `withApiAuthRequired`. After ceiling → should return 401. |
| **#15 — `updateSession()`** | Button that calls a Server Action running `updateSession({ ...session, user: { ...session.user, testKey: true } })`. After ceiling → should throw "user not authenticated". |
| **#6/#7 — At-login rejection** | Already documented in README. Add a UI warning on the home page when no `session_expiry` claim is found in the session, so the tester knows the Post-Login Action is not yet bound. |
| **#10 — Middleware rolling session** | Implicitly exercised by every request, but add a panel showing `session.internal.createdAt` (the rolling timestamp) so you can observe it stop updating once the ceiling passes. |

MFA, passkey enrollment, connection tokens, and CIBA require additional tenant-level setup (MFA policies, passkey-enabled apps, Token Vault, social connections) and are not practical to include in a standalone example.
