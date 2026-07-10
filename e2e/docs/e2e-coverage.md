# E2E Test Coverage Reference

**Total: 329 tests across 17 spec files**  
Run: `pnpm test` (boots Next.js test-app on port 3000)  
Config: `playwright.config.ts` — `testDir: "./e2e"`, chromium only

---

## Folder Structure

```
e2e/
  core/        — always runs; no external auth required (session injection or real login)
  features/    — always runs; tests SDK features against the standard Auth0 app
  platform/    — gated behind env vars; each folder targets a separate Auth0 application
  helpers.ts   — loginWithAuth0(), injectSession(), logout(), EMAIL
  test-app/    — Next.js app that implements all routes used by the specs
  docs/        — this file + env var templates
```

---

## core/ — 163 tests

### `core/handlers/auth-handlers.spec.ts` — 57 tests

Covers every handler dispatched by `auth0.middleware()` against the SDK's built-in `/auth/*` routes.

**handleLogin — /auth/login** (17)
- redirects to the authorization server
- redirects to returnTo path after successful login — App Router / Pages Router
- forwards screen_hint, connection, audience, scope params to authorize URL
- rejects invalid challengeMode with 400 / accepts popup without error
- rejects non-numeric max_age with 400 / accepts max_age=0
- authorize URL uses PKCE (code_challenge + S256)
- authorize URL contains nonce and state
- sets redirect_uri to /auth/callback
- default scope includes openid, response_type=code, client_id present
- ignores cross-origin returnTo (sanitized to default path)

**handleCallback — /auth/callback** (6)
- rejects callback with no state parameter / no parameters at all
- returns error for access_denied and login_required from Auth0
- sets httpOnly session cookie on successful callback
- removes transaction cookie after successful callback

**handleLogout — /auth/logout** (11)
- clears session cookie on logout
- renders unauthenticated state after logout — App Router / Pages Router
- forwards federated flag, returnTo as post_logout_redirect_uri, state param
- redirects even when no session exists
- omits logout_hint / id_token_hint when no session
- includes logout_hint and id_token_hint when session present

**handleProfile — /auth/profile** (4)
- returns 401 when unauthenticated
- returns user claims when authenticated
- sets Cache-Control: no-store
- excludes tokenSet and internal fields from response

**handleAccessToken — /auth/access-token** (14)
- returns 401 when unauthenticated (with code + message fields)
- response shape: token string, expires_at, expires_in, scope, token_type
- expires_in=0 / expires_at=0 when expiresAt not set
- returns 401 session_expired with IPSIE session ceiling passed; clears session cookie
- returns 401 missing_refresh_token when expired with no refresh token
- forwards ?audience, ?scope, ?mergeScopes=false query params

**auth0.middleware()** (4)
- allows public routes through (no redirect)
- intercepts /auth/* routes
- sets httpOnly SameSite=Lax session cookie
- does not intercept static asset paths (_next/static)

---

### `core/next/auth-next.spec.ts` — 27 tests

Parametrized across **App Router** and **Pages Router** via `for...of ROUTERS`. All tests run twice.

**getSession() — server component** (×2 each)
- returns null without a session / returns user when session injected

**useUser() — client component** (×2 each)
- shows unauthenticated without a session / shows user email when authenticated

**getAccessToken() client helper** (×2 each)
- returns 401 without session / returns token with session

**getAccessToken() — API route** (×2 each)
- returns 401 without session / returns token with session

**updateSession() — API route** (×2 each)
- returns 401 without session / updates session fields and returns 200

**withPageAuthRequired()** (×2 each)
- redirects to login when unauthenticated / renders page when authenticated

**withApiAuthRequired()** (×2 each)
- returns 401 without session / returns 200 with session

**Server Action — updateSession** (App Router only, 3 tests)
- Server Action is a function / updates session when authenticated / returns 401 when not authenticated

---

### `core/session/auth-session.spec.ts` — 28 tests

Covers session lifecycle and constructor option variants (named `Auth0Client` instances).

**Session lifecycle** (8)
- getSession() returns null without cookie
- getSession() returns user after inject / after real login
- updateSession() persists changes readable by subsequent getSession()
- logout clears session (cookie absent after logout)
- session cookie is httpOnly + SameSite=Lax
- cookie is a JWE (starts with `ey`, not plaintext)
- user email not visible in raw cookie value

**logoutStrategy: 'v2'** (1) — /auth/logout via v2 client returns redirect location
**includeIdTokenHintInOIDCLogoutUrl: false** (2) — logout URL omits id_token_hint
**noContentProfileResponseWhenUnauthenticated: true** (2) — /auth/profile returns 204 not 401
**enableAccessTokenEndpoint: false** (2) — /auth/access-token returns 404
**session.cookie.name custom** (2) — custom cookie name set + read correctly
**beforeSessionSaved hook** (2) — injected claim visible in session.user
**signInReturnToPath** (2) — unauthenticated visit redirects to configured path
**onCallback hook** (2) — hook redirect fires; session contains hook-injected field
**transactionCookie prefix** (2) — custom prefix used for transaction cookie; login proceeds

---

### `core/session/auth-stateful-session.spec.ts` — 9 tests

SQLite `SessionDataStore` via `node:sqlite`. Test-app: `lib/auth0-stateful.ts` + `api/stateful/*`.

**Cookie shape** (1) — login creates DB record; cookie holds only opaque JWE ID; email not in cookie
**getSession() reads from DB** (2) — returns session from DB; returns null when DB record deleted (revocation)
**Logout** (2) — logout deletes DB record; getSession() returns null after logout
**updateSession()** (2) — persists changes in DB; cookie value unchanged after update
**Session injection** (1) — stateless session injected via standard endpoint is not readable by stateful client
**Revocation race guard** (1) — update after server-side revocation does not recreate session

---

### `core/tokens/auth-tokens.spec.ts` — 40 tests

**getAccessTokenForConnection()** (2) — 401 without session; 400/403 when authenticated (no federated token)
**customTokenExchange()** (2) — 401 without session; 400 with invalid subject token when authenticated
**connectAccount() — /auth/connect** (3) — redirects unauthenticated user to login; authenticated user gets connect link; route exists (not 404/405)
**handleBackChannelLogout — /auth/backchannel-logout** (3) — 400 on missing logout_token; POST accepted (not 405); GET returns non-200
**/me/* proxy** (2) — GET /me/v1/authentication-methods 401 without session; reachable when authenticated
**/my-org/* proxy** (2) — GET /my-org/v1/members 401 without session; reachable when authenticated
**handleAccessToken behavioral depth** (8) — error code+message, response shape (token/expires_at/expires_in/scope), expires_in math, ?audience, ?scope, ?mergeScopes=false, injected valid token returns 200, expired no-refresh returns 401
**getAccessToken() silent refresh** (1) — near-expired token triggers refresh attempt
**Rolling session** (2) — cookie maxAge reset after activity; logout clears session regardless of TTL
**getAccessToken({ refresh: true })** (3) — 401 without session; 401 missing_refresh_token with no refreshToken; refreshes to new token when refreshToken present
**tokenRefreshBuffer: 3600** (2) — token within buffer window triggers refresh; fresh token outside buffer returned as-is

---

### `core/tokens/auth-mrrt.spec.ts` — 4 tests `@integration`

All skip unless `TEST_MRRT_AUDIENCE_B` is set.

- getAccessToken() with audience A returns scoped token
- audience A vs B return different tokens
- second call for same audience returns cached token
- tokens for different audiences stored independently in session

---

## features/ — 112 tests

### `features/mfa/mfa.spec.ts` — 32 tests

**Server auth0.mfa.*** (8) — getAuthenticators, challenge, enroll, verify: each returns 401 without session; SDK error with bad mfaToken (not 500)
**Middleware routes /auth/mfa/*** (4) — authenticators, challenge, verify, associate: each registered (not 404/405)
**Client mfa singleton** (3) — challengeWithPopup triggers popup flow; GET /auth/mfa/authenticators via client fetch; POST /auth/mfa/challenge via client fetch

*(plus additional describe blocks — see spec file for full list)*

---

### `features/passkey/passkey.spec.ts` — 34 tests

**Server auth0.passkey.*** (10) — register, challenge, getToken, enrollmentChallenge (401+response), enrollmentVerify (401+error): each returns 401 without session or SDK error
**Middleware routes /auth/passkey/*** (5) — register, challenge, get-token, enrollment-challenge, enrollment-verify: each registered
**Client passkey singleton** (10) — signup, login, serializeCredential, enrollment flow via /app-router/passkey page

---

### `features/passwordless/passwordless.spec.ts` — 30 tests

**Server auth0.passwordless.*** (10) — start, verify, challengeWithEmail, challengeWithPhoneNumber, loginWithOtp: each returns SDK error (not 500)
**Middleware routes /auth/passwordless/*** (4) — start, verify, otp/challenge, otp/token: each registered
**Client passwordless singleton** (8) — start, verify, challengeWithEmail, loginWithOtp via /app-router/passwordless page

---

### `features/backchannel-logout/backchannel-logout.spec.ts` — 9 tests

**Handler wiring** (7) — POST accepted (not 404/405); GET returns non-200; POST with empty body → 400; missing logout_token → 400; structurally invalid JWT → 400; well-formed unsigned JWT (alg=none) → 400; error body non-empty
**Stateful revocation guard** (1) — session survives rejected BCLO (session still valid after 400 response)
**@integration gated** (1) — valid logout_token returns 200 (requires `TEST_BCLO_LOGOUT_TOKEN`)

---

### `features/connected-accounts/connected-accounts.spec.ts` — 12 tests

**/auth/connect handler** (4) — unauthenticated redirected to login; authenticated redirected to Auth0 (3xx); not 404/405; returnTo passes through
**connect-account page** (3) — unauthenticated shows "unauthenticated" status; authenticated shows connect link; link href contains connection + returnTo
**getAccessTokenForConnection()** (5) — 401 without session (with error body); not 404/500 when authenticated; ?connection forwarded; not 405; missing param falls back to default

---

### `features/cte/cte.spec.ts` — 10 tests

**Authentication guard** (3) — 401 without session (with error body); GET not accepted
**SDK error forwarding** (3) — invalid subjectToken → 400/401/403 (not 500); 400 body has error; missing subjectToken → 400
**Request body forwarding** (3) — subjectTokenType forwarded; audience forwarded; all three fields together
**@integration gated** (1) — valid subject token returns token set (requires `TEST_CTE_SUBJECT_TOKEN`)

---

## platform/ — 54 tests (all gated behind env vars)

All platform specs call `test.skip(...)` at the top of the file when required env vars are absent. `pnpm test` passes with zero failures when no platform env is configured.

### `platform/edge/edge.spec.ts` — 21 tests

No extra env vars required — runs against the standard Auth0 app using `proxy.ts` middleware.

**Middleware routing** (6) — /auth/login intercepts → redirects to Auth0; /auth/logout intercepted; /auth/callback wired (not 404); / passes through; _next/static bypasses
**Session propagation** (4) — injected session readable in route handler; 401 without session; protected page accessible with session; withPageAuthRequired redirects without session
**Cookie attributes** (3) — httpOnly after login; SameSite=Lax; cookie cleared after logout
**Rolling session** (1) — expiry maintained/extended on activity
**Chunked cookies** (1) — large session splits across __session__0/__session__1 chunks; readable regardless
**Matcher exclusions** (2) — robots.txt / favicon.ico not blocked by middleware

---

### `platform/dpop/dpop.spec.ts` — 5 tests `@integration`

**Requires:** `AUTH0_DPOP_CLIENT_ID`, `AUTH0_DPOP_CLIENT_SECRET`  
Optional: `TEST_DPOP_CONNECTION`

- Login completes; access token contains cnf/jkt claim
- getAccessToken() returns token when authenticated
- Access token is DPoP-bound (3-part JWT)
- Force-refresh returns DPoP-bound token
- getAccessTokenForConnection() returns DPoP-bound connection token (requires `TEST_DPOP_CONNECTION`)

---

### `platform/mtls/mtls.spec.ts` — 5 tests `@integration`

**Requires:** `AUTH0_MTLS_CLIENT_ID`, `AUTH0_MTLS_CLIENT_SECRET`, `TEST_MTLS_CERT_PATH`  
Optional: `TEST_MTLS_CONNECTION`

- Login completes
- Access token contains cnf/x5t#S256 (certificate thumbprint)
- getAccessToken() returns token from mTLS endpoint
- Force-refresh returns certificate-bound token
- getAccessTokenForConnection() via mTLS endpoint (requires `TEST_MTLS_CONNECTION`)

---

### `platform/mcd/mcd.spec.ts` — 6 tests `@integration`

**Requires:** `AUTH0_MCD_CLIENT_ID`, `TEST_MCD_CUSTOM_DOMAIN`  
Optional: `TEST_MCD_SECOND_DOMAIN`

- /auth/login redirects to configured custom domain
- Login completes and sets session
- session.user contains sub + email after MCD login
- ID token iss claim matches configured custom domain
- Cross-domain session validity (requires `TEST_MCD_SECOND_DOMAIN`)
- getAccessToken() returns token after MCD login

---

### `platform/ipsie/ipsie.spec.ts` — 6 tests `@integration`

**Requires:** `AUTH0_IPSIE_CLIENT_ID`, `TEST_IPSIE_ENTERPRISE_CONNECTION`  
Optional: `TEST_IPSIE_BCLO_TOKEN`, `TEST_IPSIE_SUBJECT_TOKEN`

- /auth/login redirects to enterprise connection authorize URL
- Enterprise login sets session with org_id or hd claim
- Session user sub present after enterprise login
- Access token retrievable after enterprise login
- Enterprise BCLO token revokes session (requires `TEST_IPSIE_BCLO_TOKEN`)
- Enterprise CTE: subject token exchanged for Auth0 token (requires `TEST_IPSIE_SUBJECT_TOKEN`)

---

## Unit-only branches (not covered in E2E)

These require protocol-level control, multi-window flows, or separate tenant infrastructure that cannot be set up in a standard E2E run.

| Branch | Reason unit-only | Unit test location |
|---|---|---|
| IPSIE session ceiling at callback | ID token `session_expiry` claim must be injected via Auth0 Action — cannot forge a signed token | `auth-client.test.ts:4240` |
| `challengeMode=popup` callback | Multi-window + cross-origin postMessage; Auth0 popup app type required | `auth-client.test.ts` popup describe block |
| `Auth0Client` with `DomainResolver` (MCD resolver mode) | Requires multiple live tenants or mocked JWKS | `auth-client.test.ts:6607–6780` |
| PAR (`pushedAuthorizationRequests: true`) | Requires per-application PAR toggle in Auth0 dashboard | `auth-client.test.ts:9562+` |
| `logoutStrategy: 'oidc'` with missing end_session_endpoint | Discovery response with no `end_session_endpoint` — cannot control from real tenant | `auth-client.test.ts:3465+` |

---

## Running subsets

```bash
# All E2E (standard Auth0 app, no platform env needed)
pnpm test

# Core tier only
npx playwright test e2e/core

# Feature tier only
npx playwright test e2e/features

# Single spec
npx playwright test e2e/core/handlers/auth-handlers.spec.ts

# Only @integration tagged tests
npx playwright test --grep "@integration"

# Platform tier (requires env files — see e2e/docs/env-templates/)
AUTH0_DPOP_CLIENT_ID=... AUTH0_DPOP_CLIENT_SECRET=... npx playwright test e2e/platform/dpop
```
