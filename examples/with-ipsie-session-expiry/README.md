# with-ipsie-session-expiry

Tests IPSIE `session_expiry` ceiling enforcement end-to-end across all affected SDK paths.

When Auth0 is configured to emit a `session_expiry` claim in the ID token, the SDK treats it as a hard, non-extendable ceiling on the local session. This example exercises every flow where ceiling enforcement fires.

---

## Setup

### 1. Auth0 tenant

#### Add the Post-Login Action

1. Go to **Auth0 Dashboard → Actions → Library → Create Action → Build from scratch**
2. Name it `IPSIE Short Ceiling`, trigger = **Post-login**
3. Paste:

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     // 120-second ceiling — adjust to taste for faster testing
     api.idToken.setCustomClaim("session_expiry", Math.floor(Date.now() / 1000) + 120);
   };
   ```

4. **Deploy** → go to **Actions → Flows → Login** → drag the action into the flow → **Apply**

> The Action is not retroactive. You must log in **fresh** after binding it (use incognito or log out first).

#### Skip consent (required if testing with a custom audience)

If `AUTH0_AUDIENCE` is set, Auth0 will prompt for consent on `offline_access`. To suppress it:
**Dashboard → Applications → your app → Advanced Settings → OAuth → Skip user consent for first-party apps → On → Save**

---

### 2. Running

```bash
cp .env.example .env.local
# Fill in AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_SECRET
# AUTH0_AUDIENCE is optional — set to an API identifier to receive a JWT access token

pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) and log in with incognito.

---

## What to test and what to look for

The page has 9 cards, each targeting a specific SDK flow. The ceiling is set to **120 seconds**. The SDK applies a **30-second leeway**, so enforcement starts at **T+90s** (ceiling − leeway).

---

### Before the ceiling (T+0 to T+89s)

All cards should show healthy state.

| Card | Expected |
|---|---|
| IPSIE Session Ceiling | Countdown ticking down, green **Active** badge |
| Middleware — Rolling Session | `createdAt` value is stable; page loads normally on refresh |
| getSession() | `{ "session": { ... } }` |
| useUser() | User object shown |
| getAccessToken() — Browser | Access token displayed |
| withApiAuthRequired() | `{ "status": 200, "body": { "protected": true } }` |
| updateSession() | `{ "success": true, "updatedAt": "..." }` |
| withPageAuthRequired() | /protected page renders with your email |

---

### Approaching ceiling (T+90s to T+120s)

The SDK starts treating the session as expired once within 30s of the ceiling.

| Card | Expected |
|---|---|
| IPSIE Session Ceiling | Yellow **Expiring soon** badge at ≤30s remaining |

---

### After the ceiling (T+90s onwards, enforcement active)

Work through each card **without refreshing the main page** (refreshing redirects to login — do the manual checks first). Use the buttons to test each flow one by one.

| Card | What to click/do | Expected result |
|---|---|---|
| **getSession()** | Click **Check Session** | `{ "session": null }` — `getSession()` returns null, same as logged-out |
| **useUser()** | Observe (auto-polls) or reload the component | `Hook error: Unauthorized` — 401 from `/auth/profile` sets `error`, `user` becomes `null` |
| **getAccessToken() — Browser** | Click **Get Access Token** | Red error box: `session_expired — the IdP session ceiling has been reached` |
| **withApiAuthRequired()** | Click **Call Protected API** | `{ "status": 401 }` — guard returns 401 before the handler runs |
| **updateSession()** | Click **Update Session** | `{ "success": false, "error": "No active session..." }` — session is null, update blocked |
| **withPageAuthRequired()** | Open [/protected](http://localhost:3000/protected) in same tab | Redirected to `/auth/login` — page guard sees null session |
| **Middleware — Rolling Session** | Refresh the main page | Redirected to `/auth/login` — middleware sees null session, rolling is skipped |

> After the last step (refreshing the main page), you will be at the login page. That is correct — `getSession()` in the root page returns null and `redirect("/auth/login")` fires.

---

### At-login rejection (separate test run)

This tests the callback path that rejects a session whose ceiling is already in the past at login time.

1. Change the Post-Login Action to emit a **past** ceiling:

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.idToken.setCustomClaim("session_expiry", Math.floor(Date.now() / 1000) - 60);
   };
   ```

2. **Deploy** the updated Action.
3. Log out, then log in again (incognito).
4. **Expected**: The callback returns a `session_expired` error — you land on an error page or the login page, never on the home page. No session is stored.

Restore the Action to `+ 120` when done.

---

## SDK flows exercised

| # | Flow | Card / endpoint | Ceiling fires at |
|---|---|---|---|
| 1 | `getSession()` | getSession card → `/api/check-session` | `getSessionWithDomainCheck` |
| 2 | `useUser()` browser hook | useUser card → `/auth/profile` | `handleProfile` → `getSessionWithDomainCheck` |
| 3 | `getAccessToken()` browser | getAccessToken card → `/auth/access-token` | `handleAccessToken` → `getTokenSet` |
| 4 | `withApiAuthRequired()` | withApiAuthRequired card → `/api/protected` | `getSessionWithDomainCheck` |
| 5 | `updateSession()` | updateSession card → `/api/update-session` | `getSession()` returns null before update |
| 6 | `withPageAuthRequired()` | `/protected` page | `getSessionWithDomainCheck` |
| 7 | Middleware rolling session | page refresh | `getSessionWithDomainCheck` |
| 8 | `handleCallback` redirect | login flow (at-login rejection test) | `isSessionCeilingInPast` |
